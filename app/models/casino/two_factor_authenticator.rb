
class CASino::TwoFactorAuthenticator < ActiveRecord::Base
  belongs_to :user

  scope :active, -> { where(active: true) }

  ENCRYPTION_SALT = 'casino two factor encryption v1'.freeze
  SIGNING_SALT    = 'casino two factor signing v1'.freeze
  KEY_LENGTH      = 32

  def secret
    stored_secret = self[:secret]
    return stored_secret unless stored_secret && stored_secret.start_with?('v1:')

    self.class.secret_encryptor.decrypt_and_verify(stored_secret.delete_prefix('v1:'))
  end

  def secret=(value)
    self[:secret] = value.nil? ? nil : 'v1:' + self.class.secret_encryptor.encrypt_and_sign(value)
  end

  def self.secret_encryptor
    secret_base = configured_two_factor_secret_key
    return @secret_encryptor if @secret_encryptor && @secret_encryptor_base == secret_base

    key_generator  = ActiveSupport::CachingKeyGenerator.new(ActiveSupport::KeyGenerator.new(secret_base))
    encryption_key = key_generator.generate_key(ENCRYPTION_SALT, KEY_LENGTH)
    signing_key    = key_generator.generate_key(SIGNING_SALT, KEY_LENGTH)

    @secret_encryptor_base = secret_base
    @secret_encryptor = ActiveSupport::MessageEncryptor.new(
      encryption_key,
      signing_key,
      cipher: 'aes-256-cbc',
      digest: 'SHA256',
      serializer: ActiveSupport::MessageEncryptor::NullSerializer
    )
  end

  def self.configured_two_factor_secret_key
    secret = if Rails.application
                Rails.application.secrets.try(:two_factor_secret_key).presence ||  ENV['CASINO_API_TOKEN']
             end

    secret || raise(ArgumentError, 'two_factor_secret_key must be configured')
  end

  def self.cleanup
    self.delete_all(['(created_at < ?) AND active = ?', self.lifetime.ago, false])
  end

  def self.lifetime
    CASino.config.two_factor_authenticator[:lifetime_inactive].seconds
  end

  def expired?
    !self.active? && (Time.now - (self.created_at || Time.now)) > self.class.lifetime
  end
end
