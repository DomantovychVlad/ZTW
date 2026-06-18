//! Живі перевірки ОС-ефектів безпеки сесії (PRD 5.10), САМОВІДНОВНІ та БЕЗ сервера.
//! Б'є ТОЧНО ті функції ядра, що їх викликає керований при подіях пульта (Blank /
//! InputLock / автоблокування). Наскрізний шлях «подія пульта → керований» окремо
//! покрито connection_smoke; тут — кінцевий ефект на ЦІЙ машині, без флейкі-мережі.
//!   cargo run -p zortilwatch-core --example security_smoke
//! Реальне заморожування вводу потребує АДМІН-терміналу.
//! Щоб ще й заблокувати Windows у кінці:  $env:ZW_TEST_AUTOLOCK=1 перед запуском.

#[cfg(not(windows))]
fn main() {
    println!("security_smoke: лише Windows");
}

#[cfg(windows)]
fn main() {
    use std::thread::sleep;
    use std::time::Duration;
    use zortilwatch_core::blank::Blanker;
    use zortilwatch_core::input::{block_physical, lock_workstation};

    // Адмін? BlockInput вдається лише з адмін-правами; миттєво знімаємо.
    let admin = {
        let ok = block_physical(true);
        if ok {
            block_physical(false);
        }
        ok
    };
    let autolock = std::env::var_os("ZW_TEST_AUTOLOCK").is_some();
    println!("АДМІН={admin}  АВТОБЛОКУВАННЯ-В-КІНЦІ={autolock}");

    // ── 1. ЗАТЕМНЕННЯ (не потребує адміна) ──
    println!("BLANK: затемнюю екран на 5с (керований показує чорне, пульт бачив би реальний)…");
    let b = Blanker::show();
    sleep(Duration::from_secs(5));
    b.hide();
    sleep(Duration::from_millis(300));
    println!("BLANK: знято ✔");

    // ── 2. БЛОК ФІЗИЧНОГО ВВОДУ ──
    if admin {
        println!(
            "INPUT-LOCK: блокую фізичний ввід на 4с — миша/клавіатура завмруть, нічого не чіпай…"
        );
        let locked = block_physical(true);
        sleep(Duration::from_secs(4));
        block_physical(false);
        println!("INPUT-LOCK: знято (заблоковано={locked}) ✔");
    } else {
        println!("INPUT-LOCK: пропущено — потрібні адмін-права (запусти з адмін-терміналу)");
    }

    // ── 3. АВТОБЛОКУВАННЯ (опційно) ──
    if autolock {
        println!("AUTO-LOCK: блокую Windows за 1с — залогінься назад.");
        sleep(Duration::from_secs(1));
        lock_workstation();
    }

    println!(
        "RESULT=OK безпека сесії перевірена (затемнення{}{})",
        if admin { " + блок вводу" } else { "" },
        if autolock {
            " + автоблокування"
        } else {
            ""
        }
    );
}
