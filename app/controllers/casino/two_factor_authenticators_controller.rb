require 'rotp'

class CASino::TwoFactorAuthenticatorsController < CASino::ApplicationController
  include CASino::SessionsHelper
  include CASino::TwoFactorAuthenticatorsHelper
  include CASino::TwoFactorAuthenticatorProcessor

  before_action :ensure_signed_in
  before_action :disable_caching

  def new
    return redirect_to sessions_path if current_user.active_two_factor_authenticator

    @two_factor_authenticator = current_user.two_factor_authenticators.create! secret: ROTP::Base32.random_base32
  end

  def create
    @two_factor_authenticator = current_user.two_factor_authenticators.where(id: params[:id]).first
    if @two_factor_authenticator && CASino::TwoFactorOtpVerifier.verify!(current_user, @two_factor_authenticator, params[:otp], allow_inactive: true)
      current_user.with_lock do
        current_ticket = current_ticket_granting_ticket
        current_user.ticket_granting_tickets.where.not(id: current_ticket.id).destroy_all
        current_ticket.service_tickets.destroy_all
        @two_factor_authenticator.update!(active: true)
        update_two_factor_enabled(true)
        current_ticket.update!(two_factor_verified_at: Time.current)
      end
      flash[:notice] = I18n.t('two_factor_authenticators.successfully_activated')
      redirect_to sessions_path
    else
      flash.now[:error] = I18n.t('two_factor_authenticators.invalid_one_time_password')
      render :new
    end
  end

  def destroy
    authenticator = current_user.two_factor_authenticators.where(id: params[:id], active: true).first
    if authenticator && CASino::TwoFactorOtpVerifier.verify!(current_user, authenticator, params[:otp])
      current_user.with_lock do
        # Disable flag first so concurrent requests never see (enabled: true, authenticator: nil)
        update_two_factor_enabled(false)
        authenticator.destroy!
        current_ticket = current_ticket_granting_ticket
        current_ticket.update_columns(two_factor_verified_at: nil)

        # Revoke all other sessions when lowering account security (triggers SLO post-commit)
        current_user.ticket_granting_tickets.where.not(id: current_ticket.id).destroy_all
      end
      flash[:notice] = I18n.t('two_factor_authenticators.successfully_deleted')
    else
      flash[:error] = I18n.t('two_factor_authenticators.invalid_one_time_password')
    end
    redirect_to sessions_path
  end

  private

  def update_two_factor_enabled(enabled)
    attributes = (current_user.extra_attributes || {}).merge(:two_factor_enabled => enabled)
    current_user.update!(extra_attributes: attributes)
    CASino.app_user_class.where(email: current_user.username).update_all(two_factor_enabled: enabled)
  end

  def disable_caching
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
  end
end
