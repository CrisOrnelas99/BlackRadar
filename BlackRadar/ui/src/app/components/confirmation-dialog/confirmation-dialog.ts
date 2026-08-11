import {
  AfterViewInit,
  Component,
  ElementRef,
  OnDestroy,
  inject,
  input,
  output,
  viewChild,
} from '@angular/core';
import { DOCUMENT } from '@angular/common';

@Component({
  selector: 'app-confirmation-dialog',
  standalone: true,
  templateUrl: './confirmation-dialog.html',
  styleUrl: './confirmation-dialog.css',
})
export class ConfirmationDialogComponent implements AfterViewInit, OnDestroy {
  private readonly document = inject(DOCUMENT);
  private previouslyFocusedElement: HTMLElement | null = null;
  private readonly dialogElement = viewChild.required<ElementRef<HTMLElement>>('dialogElement');

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

  ngAfterViewInit(): void {
    this.previouslyFocusedElement = this.document.activeElement as HTMLElement | null;
    this.focusInitialElement();
  }

  ngOnDestroy(): void {
    this.restoreFocus();
  }

  handleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      if (!this.cancelDisabled()) {
        event.preventDefault();
        this.emitCancel();
      }

      return;
    }

    if (event.key !== 'Tab') {
      return;
    }

    const focusableElements = this.getFocusableElements();

    if (focusableElements.length === 0) {
      event.preventDefault();
      this.dialogElement().nativeElement.focus();
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    const activeElement = this.document.activeElement;

    if (event.shiftKey && activeElement === firstElement) {
      event.preventDefault();
      lastElement.focus();
      return;
    }

    if (!event.shiftKey && activeElement === lastElement) {
      event.preventDefault();
      firstElement.focus();
    }
  }

  emitCancel(): void {
    this.cancel.emit();
  }

  emitConfirm(): void {
    this.confirm.emit();
  }

  private focusInitialElement(): void {
    const firstFocusableElement = this.getFocusableElements()[0];

    if (firstFocusableElement) {
      firstFocusableElement.focus();
      return;
    }

    this.dialogElement().nativeElement.focus();
  }

  private restoreFocus(): void {
    if (this.previouslyFocusedElement?.isConnected) {
      this.previouslyFocusedElement.focus();
    }
  }

  private getFocusableElements(): HTMLElement[] {
    return Array.from(
      this.dialogElement().nativeElement.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((element) => !element.hasAttribute('disabled'));
  }
}
