require 'user_agent'

class CASino::TicketGrantingTicket < ActiveRecord::Base
  include CASino::ModelConcern::Ticket
  include CASino::ModelConcern::BrowserInfo

  self.ticket_prefix = 'TGC'.freeze

  belongs_to :user
  has_many :service_tickets, dependent: :destroy

  scope :active, -> { where(awaiting_two_factor_authentication: false).order('updated_at DESC') }

  # Optional: Configure maximum age for a 2FA verification (nil = valid for entire TGT lifetime)
  TWO_FACTOR_VERIFICATION_TTL = nil # e.g., 24.hours

  def self.cleanup(user = nil)
    if user.nil?
      base = self
    else
      base = user.ticket_granting_tickets
    end
    tgts = base.where([
      '(created_at < ? AND awaiting_two_factor_authentication = ?) OR (created_at < ? AND long_term = ?) OR created_at < ?',
      CASino.config.two_factor_authenticator[:timeout].seconds.ago,
      true,
      CASino.config.ticket_granting_ticket[:lifetime].seconds.ago,
      false,
      CASino.config.ticket_granting_ticket[:lifetime_long_term].seconds.ago
    ])
    CASino::ServiceTicket.where(ticket_granting_ticket_id: tgts).destroy_all
    tgts.destroy_all
  end

  def same_user?(other_ticket)
    if other_ticket.nil?
      false
    else
      other_ticket.user_id == self.user_id
    end
  end

  # Determines whether this ticket satisfies all primary and two-factor authentication requirements to mint Service Tickets.
  def two_factor_authenticated?
    return false unless ticket_active?
    return true unless two_factor_required?

    two_factor_verification_valid?
  end

  def ticket_active?
    return false if expired? || awaiting_two_factor_authentication? || user.nil?

    true
  end

  def two_factor_required?
    user.two_factor_enabled? || user.active_two_factor_authenticator.present?
  end

  def two_factor_verification_valid?
    return false if two_factor_verified_at.blank?
    return true if TWO_FACTOR_VERIFICATION_TTL.nil?

    two_factor_verified_at >= TWO_FACTOR_VERIFICATION_TTL.ago
  end

  def expired?
    if awaiting_two_factor_authentication?
      lifetime = CASino.config.two_factor_authenticator[:timeout]
    elsif long_term?
      lifetime = CASino.config.ticket_granting_ticket[:lifetime_long_term]
    else
      lifetime = CASino.config.ticket_granting_ticket[:lifetime]
    end
    (Time.now - (self.created_at || Time.now)) > lifetime
  end
end
