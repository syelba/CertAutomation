
# MongoDB Certificate Manager - Maintenance Guide

This guide will help you update and maintain your Flask + MongoDB certificate management app.

---

## 📁 Project Structure

```
project/
│
├── app.py               # Flask backend
├── .env                 # Environment variables (DB credentials, etc.)
├── index3.html          # Frontend (HTML/JS)
└── requirements.txt     # Python dependencies (optional)
```

---

## ✅ Adding Fields to the Form

1. **Update HTML form** in `index3.html`
2. **Handle it in Flask** (`app.py`)

### Example: Add `expiration_date`

**HTML:**
```html
<input type="text" name="expiration_date" placeholder="Expiration Date">
```

**Flask `/add`:**
```python
data.setdefault("expiration_date", "")
```

---

## 🔁 Updating a Certificate

- Fill in the Object ID and fields you want to update.
- Unfilled fields will remain unchanged.

Make sure all new fields are added in both frontend and backend.

---

## ❌ Deleting a Certificate

- Provide the `_id` of the document.
- Use the delete field and button.

---

## 🔒 Environment Variables

Ensure `.env` file contains:

```
DBuser=your_user
DBpassword=your_password
DBip=127.0.0.1
DBname=certDB
CollectionName=certs
```

**Never upload this file publicly.**

---

## ▶️ Running the App

```bash
python app.py
```

Then go to: [http://localhost:5000](http://localhost:5000)

---

## 📦 Creating requirements.txt

Generate:
```bash
pip freeze > requirements.txt
```

Install:
```bash
pip install -r requirements.txt
```

---

## ✅ Tips

- Use `print(data)` in Flask to debug requests.
- Check browser DevTools → Network tab to inspect API calls.
- Regularly backup MongoDB.
