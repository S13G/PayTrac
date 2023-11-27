from django.template.loader import render_to_string

from utilities.emails import send_email


def send_invoice_email(user, invoice, template=None):
    # Compose the email subject and content
    subject = 'Invoice'
    recipient = [user.email]
    context = {'from': user.full_name, 'account_number': user.wallet.account_number, 'bank_name': user.wallet.bank_name,
               "issued_on": invoice.issued_on, "due_on": invoice.due_on, "comment": invoice.comment,
               "total_price": invoice.total_price, "invoice_number": invoice.invoice_number}
    message = render_to_string(template, context)

    # Send the email
    send_email(subject, recipient, message=message, template=template, context=context)
