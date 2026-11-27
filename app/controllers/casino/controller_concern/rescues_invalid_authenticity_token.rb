module CASino::ControllerConcern::RescuesInvalidAuthenticityToken
  extend ActiveSupport::Concern

  included do
    rescue_from ActionController::InvalidAuthenticityToken, with: :handle_invalid_authenticity_token
  end

  def handle_invalid_authenticity_token
    if signed_in?
      flash[:notice] = I18n.t('sessions.your_active_sessions')
      redirect_to sessions_path
    else
      flash[:alert] = I18n.t('sessions.end_session')
      redirect_to login_path
    end
  end
end
