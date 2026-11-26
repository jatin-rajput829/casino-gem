class CASino::SessionsController < CASino::ApplicationController
  include CASino::SessionsHelper
  include CASino::AuthenticationProcessor
  include CASino::TwoFactorAuthenticatorProcessor

  before_action :validate_login_ticket, only: [:create]
  before_action :ensure_service_allowed, only: [:new, :create]
  before_action :load_pending_two_factor_ticket, only: [:validate_otp]
  before_action :ensure_signed_in, only: [:index, :destroy]

  def index
    @ticket_granting_tickets = current_user.ticket_granting_tickets.active
    @two_factor_authenticators = current_user.two_factor_authenticators.active
    @login_attempts = current_user.login_attempts.order(created_at: :desc).first(5)
  end

  def new
    tgt = current_ticket_granting_ticket
    return handle_signed_in(tgt) unless params[:renew] || tgt.nil?
    redirect_to(params[:service]) if params[:gateway] && params[:service].present?
  end

  def create
    validation_result = validate_login_credentials(params[:username], params[:password])
    if !validation_result
      log_failed_login params[:username]
      show_login_error I18n.t('login_credential_acceptor.invalid_login_credentials')
    else
      sign_in(validation_result, long_term: params[:rememberMe], credentials_supplied: true)
    end
  end

  def destroy
    tickets = current_user.ticket_granting_tickets.where(id: params[:id])
    tickets.first.destroy if tickets.any?
    redirect_to sessions_path
  end

  def destroy_others
    current_user
      .ticket_granting_tickets
      .where('id != ?', current_ticket_granting_ticket.id)
      .destroy_all if signed_in?
    redirect_to params[:service] || sessions_path
  end

  def logout
    sign_out
    @url = params[:url]
    if params[:service].present? && service_allowed?(params[:service])
      redirect_to params[:service], status: :see_other
    end
  end

  def validate_otp
    user = @ticket_granting_ticket.user
    verified = false
    user.with_lock do
      @ticket_granting_ticket.reload
      if @ticket_granting_ticket.awaiting_two_factor_authentication? && !@ticket_granting_ticket.expired? &&
         ::TwoFactorOtpVerifier.verify!(user, user.active_two_factor_authenticator, params[:otp])
        @ticket_granting_ticket.update!(awaiting_two_factor_authentication: false, two_factor_verified_at: Time.current)
        verified = true
      end
    end

    unless verified
      create_login_attempt(user, false)
      flash.now[:error] = I18n.t('validate_otp.invalid_otp')
      return render 'casino/sessions/validate_otp', status: :forbidden
    end

    complete_two_factor_sign_in(@ticket_granting_ticket)
  end

  private

  def show_login_error(message)
    flash.now[:error] = message
    render :new, status: :forbidden
  end

  def validate_login_ticket
    unless CASino::LoginTicket.consume(params[:lt])
      show_login_error I18n.t('login_credential_acceptor.invalid_login_ticket')
    end
  end

  def ensure_service_allowed
    if params[:service].present? && !service_allowed?(params[:service])
      render 'service_not_allowed', status: :forbidden
    end
  end

end
