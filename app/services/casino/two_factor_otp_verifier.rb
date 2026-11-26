require 'rotp'

class CASino::TwoFactorOtpVerifier
  MAX_FAILED_ATTEMPTS = 5
  LOCK_DURATION = 10.minutes
  DRIFT_SECONDS = 30

  def self.verify!(casino_user, authenticator, code, options = {})
    now = options.fetch(:now, Time.current)
    casino_user.with_lock do
      return false if casino_user.otp_locked_until && casino_user.otp_locked_until > now

      factor = CASino::TwoFactorAuthenticator.lock.where(id: authenticator.try(:id), user_id: casino_user.id).first
      return false unless factor && !factor.expired?
      return false unless factor.active? || options[:allow_inactive]

      step = matching_step(factor, code, now)
      if step && (factor.last_otp_step.nil? || step > factor.last_otp_step)
        factor.update!(last_otp_step: step)
        casino_user.update!(otp_failed_attempts: 0, otp_locked_until: nil)
        true
      else
        failures = casino_user.otp_failed_attempts + 1
        locked_until = failures >= MAX_FAILED_ATTEMPTS ? now + LOCK_DURATION : nil
        casino_user.update!(otp_failed_attempts: failures >= MAX_FAILED_ATTEMPTS ? 0 : failures,
                            otp_locked_until: locked_until)
        false
      end
    end
  end

  def self.matching_step(factor, code, now)
    return nil unless code.is_a?(String) && code.match?(/\A[0-9]{6}\z/)

    totp = ROTP::TOTP.new(factor.secret)
    steps = [-DRIFT_SECONDS, 0, DRIFT_SECONDS].map { |offset| (now.to_i + offset) / totp.interval }.uniq
    steps.reverse.find do |step|
      expected = totp.at(Time.at(step * totp.interval)).to_s.rjust(6, '0')
      ActiveSupport::SecurityUtils.secure_compare(expected, code)
    end
  end
  private_class_method :matching_step
end
