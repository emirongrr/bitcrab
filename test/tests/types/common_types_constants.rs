use bitcrab_common::types::constants::*;


    #[test]
    fn max_money_equals_21m_btc() {
        assert_eq!(MAX_MONEY, 21_000_000 * COIN);
        assert_eq!(MAX_MONEY, 2_100_000_000_000_000);
    }

    #[test]
    fn target_timespan_is_two_weeks_in_seconds() {
        assert_eq!(TARGET_TIMESPAN, 2_016 * 600);
        assert_eq!(TARGET_TIMESPAN, 1_209_600); // 14 days
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn coinbase_script_bounds_are_sane() {
        assert!(MIN_COINBASE_SCRIPT_SIZE < MAX_COINBASE_SCRIPT_SIZE);
        assert_eq!(MIN_COINBASE_SCRIPT_SIZE, 2);
        assert_eq!(MAX_COINBASE_SCRIPT_SIZE, 100);
    }

    #[test]
    fn halving_schedule_fits_in_u64() {
        // Total supply across all halvings must not overflow u64
        let mut total: u64 = 0;
        let mut reward = INITIAL_BLOCK_REWARD;
        for _ in 0..34 {
            // 34 halvings covers the full emission schedule
            let epoch_total = reward.saturating_mul(HALVING_INTERVAL as u64);
            total = total.saturating_add(epoch_total);
            reward /= 2;
        }
        assert!(total <= MAX_MONEY);
        assert!(total > 0);
    }
