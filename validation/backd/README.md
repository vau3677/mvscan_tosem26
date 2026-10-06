# Preserved local Backd regression tests

These two files contain locally authored tests absent from the remote workspace:

- tests/fee_handler/test_fee_calculation.py: test_independent_keeper_fee_update_can_make_total_fees_exceed_one
- tests/amm_gauge/test_inflation_accrual_amm.py: test_amm_decay_checkpoint_applies_new_rate_to_elapsed_old_rate_interval

Their complete original file contents are preserved under authored-tests/. They belong to the Backd Brownie test project; they are not standalone evaluation-infrastructure tests. They were preserved without changing the frozen benchmark inputs or counting them as newly executed publication experiments.
