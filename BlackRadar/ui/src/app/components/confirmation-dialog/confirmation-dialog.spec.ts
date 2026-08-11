import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ConfirmationDialogComponent } from './confirmation-dialog';

describe('ConfirmationDialogComponent', () => {
  let fixture: ComponentFixture<ConfirmationDialogComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ConfirmationDialogComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(ConfirmationDialogComponent);
    fixture.componentRef.setInput('dialogId', 'test-confirmation-dialog');
    fixture.componentRef.setInput('title', 'Delete asset');
    fixture.componentRef.setInput('message', 'Delete this asset permanently?');
    fixture.componentRef.setInput('confirmLabel', 'Delete');
    fixture.detectChanges();
  });

  it('moves focus into the dialog when opened and restores it when closed', () => {
    const openerButton = document.createElement('button');
    document.body.appendChild(openerButton);
    openerButton.focus();

    fixture.destroy();

    const dialogFixture = TestBed.createComponent(ConfirmationDialogComponent);
    dialogFixture.componentRef.setInput('dialogId', 'focus-confirmation-dialog');
    dialogFixture.componentRef.setInput('title', 'Delete asset');
    dialogFixture.componentRef.setInput('message', 'Delete this asset permanently?');
    dialogFixture.componentRef.setInput('confirmLabel', 'Delete');
    dialogFixture.detectChanges();

    const dialogElement = dialogFixture.nativeElement as HTMLElement;
    const cancelButton = dialogElement.querySelector(
      '.confirmation-dialog-cancel',
    ) as HTMLButtonElement;

    expect(document.activeElement).toBe(cancelButton);

    dialogFixture.destroy();

    expect(document.activeElement).toBe(openerButton);

    openerButton.remove();
  });

  it('traps tab navigation within the dialog controls', () => {
    const dialogElement = fixture.nativeElement as HTMLElement;
    const cancelButton = dialogElement.querySelector(
      '.confirmation-dialog-cancel',
    ) as HTMLButtonElement;
    const confirmButton = dialogElement.querySelector(
      '.confirmation-dialog-confirm',
    ) as HTMLButtonElement;

    confirmButton.focus();
    confirmButton.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }),
    );

    expect(document.activeElement).toBe(cancelButton);

    cancelButton.focus();
    cancelButton.dispatchEvent(
      new KeyboardEvent('keydown', {
        key: 'Tab',
        shiftKey: true,
        bubbles: true,
        cancelable: true,
      }),
    );

    expect(document.activeElement).toBe(confirmButton);
  });

  it('cancels on Escape only when cancel is enabled', () => {
    const emitCancelSpy = vi.spyOn(fixture.componentInstance.cancel, 'emit');
    const dialogElement = fixture.nativeElement.querySelector(
      '.confirmation-dialog',
    ) as HTMLElement;

    dialogElement.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }),
    );

    expect(emitCancelSpy).toHaveBeenCalledTimes(1);

    fixture.componentRef.setInput('cancelDisabled', true);
    fixture.detectChanges();

    dialogElement.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }),
    );

    expect(emitCancelSpy).toHaveBeenCalledTimes(1);
  });
});
