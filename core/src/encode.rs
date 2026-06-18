//! Кодування екрана в H.264 через Media Foundation.
//!
//! Stage 2: програмний синхронний H.264 MFT + Video Processor MFT (BGRA8 -> NV12),
//! low-latency Constrained Baseline (для WebRTC/браузера). MF — це кодек ОС, тож без
//! патентних роялті й без сторонніх залежностей. Апаратний async-MFT — апгрейд далі.

#[derive(Debug)]
pub struct EncodeError(pub String);

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "encode error: {}", self.0)
    }
}

impl std::error::Error for EncodeError {}

#[cfg(windows)]
mod mf {
    use super::EncodeError;
    use windows::core::Interface;
    use windows::Win32::Foundation::E_FAIL;
    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Variant::VARIANT;

    #[inline]
    fn pack(hi: u32, lo: u32) -> u64 {
        ((hi as u64) << 32) | (lo as u64)
    }

    fn map<T>(r: windows::core::Result<T>) -> Result<T, EncodeError> {
        r.map_err(|e| EncodeError(e.to_string()))
    }

    /// Кодувальник H.264: тримає два MFT (конвертер кольору + енкодер) і час кадру.
    pub struct H264Encoder {
        vproc: IMFTransform,
        enc: IMFTransform,
        width: u32,
        height: u32,
        fps: u32,
        frame_index: i64,
    }

    impl H264Encoder {
        pub fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<Self, EncodeError> {
            Self::new_scaled(width, height, width, height, fps, bitrate)
        }

        /// Кодувальник зі зміною роздільності: вхід BGRA `in_w`×`in_h`, вихідний потік
        /// `out_w`×`out_h` (масштабує Video Processor MFT). NV12 вимагає парних розмірів —
        /// вирівнюються вниз.
        pub fn new_scaled(
            in_w: u32,
            in_h: u32,
            out_w: u32,
            out_h: u32,
            fps: u32,
            bitrate: u32,
        ) -> Result<Self, EncodeError> {
            let (out_w, out_h) = (out_w & !1, out_h & !1);
            unsafe { map(Self::new_inner(in_w, in_h, out_w, out_h, fps, bitrate)) }
        }

        unsafe fn new_inner(
            width: u32,
            height: u32,
            out_w: u32,
            out_h: u32,
            fps: u32,
            bitrate: u32,
        ) -> windows::core::Result<Self> {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
            MFStartup(MF_VERSION, MFSTARTUP_FULL)?;

            // --- Video Processor MFT: RGB32 (BGRA8) -> NV12 ---
            let vproc: IMFTransform =
                CoCreateInstance(&CLSID_VideoProcessorMFT, None, CLSCTX_INPROC_SERVER)?;

            let vp_in = MFCreateMediaType()?;
            vp_in.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            vp_in.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_RGB32)?;
            vp_in.SetUINT64(&MF_MT_FRAME_SIZE, pack(width, height))?;
            vp_in.SetUINT64(&MF_MT_FRAME_RATE, pack(fps, 1))?;
            vp_in.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            vp_in.SetUINT32(&MF_MT_DEFAULT_STRIDE, width * 4)?;

            // Вихід VP = цільова роздільність потоку (VP масштабує, якщо відрізняється).
            let vp_out = MFCreateMediaType()?;
            vp_out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            vp_out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            vp_out.SetUINT64(&MF_MT_FRAME_SIZE, pack(out_w, out_h))?;
            vp_out.SetUINT64(&MF_MT_FRAME_RATE, pack(fps, 1))?;
            vp_out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;

            vproc.SetOutputType(0, &vp_out, 0)?;
            vproc.SetInputType(0, &vp_in, 0)?;
            vproc.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;

            // --- H.264 синхронний програмний енкодер: NV12 -> H264 ---
            let enc = create_h264_encoder_sync()?;

            // Low-latency + CBR через ICodecAPI (per-frame вихід для реального часу).
            let codec: ICodecAPI = enc.cast()?;
            codec.SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(true))?;
            codec.SetValue(
                &CODECAPI_AVEncCommonRateControlMode,
                &VARIANT::from(eAVEncCommonRateControlMode_CBR.0 as u32),
            )?;
            codec.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &VARIANT::from(bitrate))?;

            let enc_out = MFCreateMediaType()?;
            enc_out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            enc_out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            enc_out.SetUINT32(&MF_MT_AVG_BITRATE, bitrate)?;
            enc_out.SetUINT64(&MF_MT_FRAME_SIZE, pack(out_w, out_h))?;
            enc_out.SetUINT64(&MF_MT_FRAME_RATE, pack(fps, 1))?;
            enc_out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
            enc_out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            enc_out.SetUINT32(
                &MF_MT_MPEG2_PROFILE,
                eAVEncH264VProfile_ConstrainedBase.0 as u32,
            )?;
            enc.SetOutputType(0, &enc_out, 0)?;

            let enc_in = MFCreateMediaType()?;
            enc_in.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            enc_in.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            enc_in.SetUINT64(&MF_MT_FRAME_SIZE, pack(out_w, out_h))?;
            enc_in.SetUINT64(&MF_MT_FRAME_RATE, pack(fps, 1))?;
            enc_in.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            enc.SetInputType(0, &enc_in, 0)?;
            enc.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;

            Ok(Self {
                vproc,
                enc,
                width: out_w,
                height: out_h,
                fps,
                frame_index: 0,
            })
        }

        /// Закодувати один щільно упакований BGRA8-кадр -> H.264 (Annex-B) байти.
        pub fn encode_bgra(&mut self, bgra: &[u8]) -> Result<Vec<u8>, EncodeError> {
            unsafe { map(self.encode_inner(bgra)) }
        }

        unsafe fn encode_inner(&mut self, bgra: &[u8]) -> windows::core::Result<Vec<u8>> {
            let dur = 10_000_000i64 / self.fps as i64;
            let pts = self.frame_index * dur;
            self.frame_index += 1;

            // BGRA8 -> NV12
            let in_sample = sample_from_bytes(bgra, pts, dur)?;
            self.vproc.ProcessInput(0, &in_sample, 0)?;
            let mut nv12 = Vec::with_capacity((self.width * self.height * 3 / 2) as usize);
            process_pull(&self.vproc, &mut nv12)?;

            // NV12 -> H264
            let nv12_sample = sample_from_bytes(&nv12, pts, dur)?;
            self.enc.ProcessInput(0, &nv12_sample, 0)?;
            let mut h264 = Vec::new();
            process_pull(&self.enc, &mut h264)?;
            Ok(h264)
        }

        /// Витягти буферизовані кадри (flush наприкінці потоку).
        pub fn drain(&mut self) -> Result<Vec<u8>, EncodeError> {
            unsafe { map(self.drain_inner()) }
        }

        unsafe fn drain_inner(&mut self) -> windows::core::Result<Vec<u8>> {
            self.enc.ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0)?;
            let mut out = Vec::new();
            process_pull(&self.enc, &mut out)?;
            Ok(out)
        }
    }

    impl Drop for H264Encoder {
        fn drop(&mut self) {
            unsafe {
                let _ = MFShutdown();
            }
        }
    }

    unsafe fn create_h264_encoder_sync() -> windows::core::Result<IMFTransform> {
        let in_info = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: MFVideoFormat_NV12,
        };
        let out_info = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: MFVideoFormat_H264,
        };
        let mut acts: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut n = 0u32;
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(&in_info),
            Some(&out_info),
            &mut acts,
            &mut n,
        )?;
        if n == 0 || acts.is_null() {
            return Err(windows::core::Error::from_hresult(E_FAIL));
        }
        let first = std::slice::from_raw_parts(acts, n as usize)[0]
            .clone()
            .ok_or_else(|| windows::core::Error::from_hresult(E_FAIL))?;
        let t: IMFTransform = first.ActivateObject()?;
        CoTaskMemFree(Some(acts as *const core::ffi::c_void));
        Ok(t)
    }

    unsafe fn sample_from_bytes(
        data: &[u8],
        pts: i64,
        dur: i64,
    ) -> windows::core::Result<IMFSample> {
        let buf = MFCreateMemoryBuffer(data.len() as u32)?;
        let mut p: *mut u8 = std::ptr::null_mut();
        buf.Lock(&mut p, None, None)?;
        std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
        buf.Unlock()?;
        buf.SetCurrentLength(data.len() as u32)?;
        let s = MFCreateSample()?;
        s.AddBuffer(&buf)?;
        s.SetSampleTime(pts)?;
        s.SetSampleDuration(dur)?;
        Ok(s)
    }

    unsafe fn process_pull(mft: &IMFTransform, out: &mut Vec<u8>) -> windows::core::Result<()> {
        let info = mft.GetOutputStreamInfo(0)?;
        let provides = (info.dwFlags
            & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32))
            != 0;
        loop {
            let mut db = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                ..Default::default()
            };
            if !provides {
                let s = MFCreateSample()?;
                let cap = info.cbSize.max(1 << 20);
                s.AddBuffer(&MFCreateMemoryBuffer(cap)?)?;
                db.pSample = std::mem::ManuallyDrop::new(Some(s));
            }
            let mut status = 0u32;
            match mft.ProcessOutput(0, std::slice::from_mut(&mut db), &mut status) {
                Ok(()) => {
                    if let Some(s) = (*db.pSample).clone() {
                        let cb = s.ConvertToContiguousBuffer()?;
                        let mut p: *mut u8 = std::ptr::null_mut();
                        let mut len = 0u32;
                        cb.Lock(&mut p, None, Some(&mut len))?;
                        out.extend_from_slice(std::slice::from_raw_parts(p, len as usize));
                        cb.Unlock()?;
                    }
                    let _ = std::mem::ManuallyDrop::take(&mut db.pSample);
                }
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => {
                    let _ = std::mem::ManuallyDrop::take(&mut db.pSample);
                    break;
                }
                Err(e) => {
                    let _ = std::mem::ManuallyDrop::take(&mut db.pSample);
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use mf::H264Encoder;
