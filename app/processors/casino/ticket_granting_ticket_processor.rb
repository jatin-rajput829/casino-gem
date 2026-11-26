module CASino::TicketGrantingTicketProcessor
  extend ActiveSupport::Concern

  include CASino::BrowserProcessor

  def find_valid_ticket_granting_ticket(ticket, user_agent, options = {})
    tgt = CASino::TicketGrantingTicket.where(ticket: ticket).first
    unless tgt.nil?
      if tgt.expired?
        Rails.logger.info "Ticket-granting ticket expired (Created: #{tgt.created_at})"
        tgt.destroy
        nil
      elsif !options[:ignore_two_factor] && !tgt.two_factor_authenticated?
        Rails.logger.info 'Ticket-granting ticket has not completed two-factor authentication'
        nil
      elsif same_browser?(tgt.user_agent, user_agent)
        tgt.user_agent = user_agent
        tgt.touch
        tgt.save!
        tgt
      else
        Rails.logger.info 'User-Agent changed: ticket-granting ticket not valid for this browser'
        nil
      end
    end
  end

  def acquire_ticket_granting_ticket(authentication_result, user_agent, user_ip, options = {})
    user_data = authentication_result[:user_data]
    user = load_or_initialize_user(authentication_result[:authenticator], user_data[:username], user_data[:extra_attributes])
    cleanup_expired_ticket_granting_tickets(user)
    two_factor_verified_this_login = user.two_factor_enabled? || user.active_two_factor_authenticator.present?
    ticket_attributes = {
      awaiting_two_factor_authentication: two_factor_verified_this_login,
      user_agent: user_agent,
      user_ip: user_ip,
      long_term: !!options[:long_term]
    }
    ticket_attributes[:two_factor_verified_at] = Time.current if two_factor_verified_this_login
    user.ticket_granting_tickets.create!(ticket_attributes)
  end

  def load_or_initialize_user(authenticator, username, extra_attributes)
    user = CASino::User
      .where(authenticator: authenticator, username: username)
      .first_or_initialize
    user.extra_attributes = extra_attributes
    user.save!
    return user
  end

  def remove_ticket_granting_ticket(ticket_granting_ticket, user_agent)
    tgt = find_valid_ticket_granting_ticket(ticket_granting_ticket, user_agent)
    tgt.destroy unless tgt.nil?
  end

  def cleanup_expired_ticket_granting_tickets(user)
    CASino::TicketGrantingTicket.cleanup(user)
  end
end
