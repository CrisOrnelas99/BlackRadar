import { Component, input, output } from '@angular/core';

@Component({
  selector: 'app-confirmation-dialog',
  standalone: true,
  templateUrl: './confirmation-dialog.html',
  styleUrl: './confirmation-dialog.css',
})
export class ConfirmationDialogComponent {
  readonly dialogId = input.required<string>();
  readonly title = input.required<string>();
  readonly message = input.required<string>();
  readonly confirmLabel = input.required<string>();
  readonly cancelLabel = input('Cancel');
  readonly confirmTone = input<'success' | 'danger' | 'primary'>('primary');
  readonly confirmDisabled = input(false);
  readonly cancelDisabled = input(false);

  readonly cancel = output<void>();
  readonly confirm = output<void>();

  emitCancel(): void {
    this.cancel.emit();
  }

  emitConfirm(): void {
    this.confirm.emit();
  }
}
