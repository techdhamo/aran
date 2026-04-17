import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IonicModule } from '@ionic/angular';

@Component({
  selector: 'app-support-page',
  standalone: true,
  imports: [CommonModule, FormsModule, IonicModule],
  template: `
    <ion-content style="--background: #F9FAFB;">
    <div style="padding: 24px; max-width: 1200px; margin: 0 auto;">
      <h1 style="font-size: 1.5rem; font-weight: 700; color: #1A1A1A; margin-bottom: 24px;">Support Portal</h1>

      <div style="display: grid; grid-template-columns: 1fr; gap: 24px;">
        <!-- On larger screens, show side by side -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 24px;">

          <!-- Ticket List -->
          <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; overflow: hidden;">
            <div style="padding: 16px 20px; border-bottom: 1px solid #E5E7EB;">
              <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">Your Tickets</h2>
            </div>
            <ion-list style="--ion-item-background: #FFFFFF;">
              <ion-item *ngFor="let ticket of tickets" style="--border-color: #F3F4F6;">
                <ion-icon [name]="ticket.status === 'Open' ? 'ellipse' : 'checkmark-circle'" 
                          [style.color]="ticket.status === 'Open' ? '#F59E0B' : '#16A34A'" slot="start" style="font-size: 14px;"></ion-icon>
                <ion-label>
                  <h3 style="font-size: 0.875rem; font-weight: 600; color: #1A1A1A;">{{ ticket.subject }}</h3>
                  <p style="font-size: 0.75rem; color: #6B7280;">{{ ticket.date }} &middot; {{ ticket.status }}</p>
                </ion-label>
                <ion-badge slot="end" [color]="ticket.priority === 'High' ? 'danger' : ticket.priority === 'Medium' ? 'warning' : 'primary'" style="font-size: 0.7rem;">
                  {{ ticket.priority }}
                </ion-badge>
              </ion-item>
            </ion-list>
          </div>

          <!-- Create Ticket Form -->
          <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; overflow: hidden;">
            <div style="padding: 16px 20px; border-bottom: 1px solid #E5E7EB;">
              <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">Create Ticket</h2>
            </div>
            <div style="padding: 20px;">
              <form (ngSubmit)="createTicket()">
                <div style="margin-bottom: 16px;">
                  <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">Subject</label>
                  <input
                    type="text"
                    [(ngModel)]="newTicket.subject"
                    name="subject"
                    placeholder="Brief description of the issue"
                    required
                    style="width: 100%; padding: 10px 14px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 0.875rem; color: #1A1A1A; box-sizing: border-box;"
                  />
                </div>
                <div style="margin-bottom: 16px;">
                  <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">Priority</label>
                  <select
                    [(ngModel)]="newTicket.priority"
                    name="priority"
                    style="width: 100%; padding: 10px 14px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 0.875rem; color: #1A1A1A; background: #FFFFFF; box-sizing: border-box;"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                  </select>
                </div>
                <div style="margin-bottom: 20px;">
                  <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">Description</label>
                  <textarea
                    [(ngModel)]="newTicket.description"
                    name="description"
                    rows="4"
                    placeholder="Describe the issue in detail..."
                    required
                    style="width: 100%; padding: 10px 14px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 0.875rem; color: #1A1A1A; resize: vertical; box-sizing: border-box;"
                  ></textarea>
                </div>
                <button
                  type="submit"
                  [disabled]="!newTicket.subject || !newTicket.description"
                  style="width: 100%; padding: 12px; background: linear-gradient(135deg, #0066CC 0%, #0052A3 100%); color: #FFFFFF; border: none; border-radius: 8px; font-size: 0.875rem; font-weight: 600; cursor: pointer; box-sizing: border-box;"
                  [style.opacity]="!newTicket.subject || !newTicket.description ? '0.5' : '1'"
                >
                  Submit Ticket
                </button>
              </form>
            </div>
          </div>

        </div>
      </div>
    </div>
    </ion-content>
  `
})
export class SupportPage {
  tickets = [
    { subject: 'SSL Pinning false positive on Android 14', date: '2026-02-23', status: 'Open', priority: 'High' },
    { subject: 'Dashboard metrics not updating', date: '2026-02-22', status: 'Open', priority: 'Medium' },
    { subject: 'SDK integration guide unclear', date: '2026-02-20', status: 'Resolved', priority: 'Low' },
    { subject: 'Need custom threat action hook', date: '2026-02-18', status: 'Resolved', priority: 'Medium' }
  ];

  newTicket = { subject: '', priority: 'Medium', description: '' };

  createTicket(): void {
    if (!this.newTicket.subject || !this.newTicket.description) return;
    this.tickets.unshift({
      subject: this.newTicket.subject,
      date: new Date().toISOString().split('T')[0],
      status: 'Open',
      priority: this.newTicket.priority
    });
    this.newTicket = { subject: '', priority: 'Medium', description: '' };
  }
}
