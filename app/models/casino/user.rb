
class CASino::User < ActiveRecord::Base
  serialize :extra_attributes, Hash

  has_many :ticket_granting_tickets
  has_many :two_factor_authenticators
  has_many :login_attempts

  def active_two_factor_authenticator
    self.two_factor_authenticators.where(active: true).first
  end

  def two_factor_enabled?
    values = extra_attributes || {}
    value =  values[:two_factor_enabled]
    value == true
  end
end
