class AddTwoFactorVerificationState < ActiveRecord::Migration
  def up
    add_column :casino_users, :otp_failed_attempts, :integer, null: false, default: 0
    add_column :casino_users, :otp_locked_until, :datetime
    add_column :casino_two_factor_authenticators, :last_otp_step, :integer, limit: 8
  end

  def down
    remove_column :casino_users, :otp_failed_attempts
    remove_column :casino_users, :otp_locked_until
    remove_column :casino_two_factor_authenticators
  end
end
