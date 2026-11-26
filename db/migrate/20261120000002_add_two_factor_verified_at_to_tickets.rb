class AddTwoFactorVerifiedAtToTickets < ActiveRecord::Migration
  def up
    add_column :casino_ticket_granting_tickets, :casino_ticket_granting_tickets, :datetime
  end

  def down
    remove_column :casino_ticket_granting_tickets, :casino_ticket_granting_tickets
  end
end
