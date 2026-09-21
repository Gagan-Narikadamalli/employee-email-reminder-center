# Employee Reminder Center — Gmail and Twilio SMS

This version analyzes the missing-appointments CSV against the **Employee Contact Info** sheet and prepares personalized employee reminder emails in Gmail Web.

## What it does

- Upload the full unfiltered appointments CSV.
- Automatically keep rows where `IsConvertable` is true and `ConvertedToTimesheet` is `0`, while excluding cancelled or deleted rows.
- Upload the employee contacts `.xlsx` workbook.
- Match the CSV to the workbook by employee name first, so updated workbook emails are used even when the CSV contains an older email.
- Count each employee's missing appointment conversions.
- Create a personalized subject and reminder message.
- Open one or all personalized reminder emails in Gmail.
- Send the normal automated SMS reminder.
- Choose **Custom one-time message** to type and send a different SMS to all matched employees with phone numbers.

The app prefills Gmail, but you review each prepared message and click Gmail's final **Send** button.

## Required environment variables

Configure `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_PHONE_NUMBER` for SMS. Gmail does not require credentials inside the app.

Keep these values in Vercel environment variables. Do not put them in source code or GitHub.

## Run on macOS / Linux

Double-click `start_mac_linux.sh` if your system allows it, or open Terminal in this folder and run:

```bash
python3 app.py
```

Then open:

```text
http://127.0.0.1:5051
```

## Run on Windows

Double-click `start_windows.bat`, or run:

```bat
python app.py
```

## Required files

### Missing appointments CSV
The CSV must contain at least:
- `Principal1Name`
- `Principal2Name`
- `StartDateTime`

The app uses `Principal1Name` as the only matching key and compares it with the `Employee` column in the Excel contact sheet. After a safe name match, both the recipient email address and phone number come from that Excel row. The CSV email is never used as a fallback.

The employee contact workbook can be saved in the browser after its first upload. Future analyses only require a new missing-appointments CSV. The saved workbook remains in that browser and can be replaced by selecting a newer workbook or removed with the **Remove saved workbook** button. Sending an SMS updates the current page without clearing the analyzed employee list.

### Employee contacts Excel
The workbook must contain a sheet named:

`Employee Contact Info`

That sheet needs columns:
- `Employee`
- `Email`

## Duplicate employee names

Keep each employee name unique in the `Employee Contact Info` sheet. If the same employee name appears more than once with different emails, the app will flag that employee for review instead of guessing.
