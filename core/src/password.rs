//! Паролі підключення (PRD 5.1).
//!
//! Одноразовий пароль генерується на КЕРОВАНОМУ пристрої, показується, діє в межах
//! сеансу й оновлюється — для разової допомоги. Постійний задає власник (зберігається
//! хешованим на сервері — argon2). Через властивість PAKE (лише 1 онлайн-спроба за
//! з'єднання) одноразовий робимо 8 однозначних алфанумерик (~40 біт), а не 6 цифр
//! (~20 біт); сервер додатково обмежує кількість спроб.

// 32 однозначні символи (без 0/O/1/I). Рівно 32 => % 256 без modulo-зсуву.
const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ONE_TIME_LEN: usize = 8;

/// Згенерувати одноразовий пароль (CSPRNG, 8 однозначних алфанумерик).
pub fn generate_one_time() -> String {
    let mut bytes = [0u8; ONE_TIME_LEN];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG failed");
    bytes
        .iter()
        .map(|&b| CHARSET[(b as usize) % CHARSET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_has_right_shape() {
        for _ in 0..500 {
            let p = generate_one_time();
            assert_eq!(p.len(), ONE_TIME_LEN);
            // Лише символи з набору; без неоднозначних 0/O/1/I.
            assert!(p.bytes().all(|b| CHARSET.contains(&b)));
            assert!(!p.contains(['0', 'O', '1', 'I']));
        }
    }

    #[test]
    fn one_time_is_varied() {
        let set: std::collections::HashSet<_> = (0..200).map(|_| generate_one_time()).collect();
        assert!(set.len() > 190);
    }
}
