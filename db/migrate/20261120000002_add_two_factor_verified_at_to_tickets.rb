class AddTwoFactorVerifiedAtToTickets < ActiveRecord::Migration
  def up
    add_column :casino_ticket_granting_tickets, :two_factor_verified_at, :datetime
  end

  def down
    remove_column :casino_ticket_granting_tickets, :two_factor_verified_at
  end
end
