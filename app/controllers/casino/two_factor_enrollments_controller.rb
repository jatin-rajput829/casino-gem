require 'rotp'

class CASino::TwoFactorEnrollmentsController < CASino::ApplicationController
  include CASino::SessionsHelper
  include CASino::TwoFactorAuthenticatorsHelper
  helper CASino::TwoFactorAuthenticatorsHelper

  before_action :load_pending_two_factor_ticket
  before_action :disable_caching

  def new
    return render 'casino/sessions/validate_otp' if pending_user.active_two_factor_authenticator

    pending_user.with_lock do
      @two_factor_authenticator = pending_authenticator
      if @two_factor_authenticator.nil? || @two_factor_authenticator.expired?
        @two_factor_authenticator.destroy if @two_factor_authenticator
        @two_factor_authenticator = pending_user.two_factor_authenticators.create!(secret: ROTP::Base32.random_base32)
      end
      session[:enrollment_authenticator_id] = @two_factor_authenticator.id
    end
  end

  def verify
    verified = false
    pending_user.with_lock do
      @ticket_granting_ticket.reload
      authenticator = pending_authenticator
      if @ticket_granting_ticket.awaiting_two_factor_authentication? && !@ticket_granting_ticket.expired? &&
        authenticator && pending_user.active_two_factor_authenticator.nil? &&
         CASino::TwoFactorOtpVerifier.verify!(pending_user, authenticator, params[:otp], allow_inactive: true)
        authenticator.update!(active: true)
        @ticket_granting_ticket.update!(awaiting_two_factor_authentication: false, two_factor_verified_at: Time.current)
        verified = true
      end
    end

    return complete_two_factor_sign_in(@ticket_granting_ticket) if verified

    @two_factor_authenticator = pending_authenticator
    @two_factor_authenticator = nil if @two_factor_authenticator && @two_factor_authenticator.expired?
    flash.now[:error] = I18n.t('two_factor_authenticators.invalid_authenticator_code')
    render :new, status: :forbidden
  end

  private

  def pending_user
    @ticket_granting_ticket.user
  end

  def pending_authenticator
    pending_user.two_factor_authenticators.where(id: session[:enrollment_authenticator_id], active: false).first
  end

  def disable_caching
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
  end
end
