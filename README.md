# Voice – Civic Issue Reporting Platform

## 📌 Project Overview
**Voice** is a web-based civic engagement platform that allows citizens to report public issues in a structured and transparent manner. The platform helps authorities monitor, manage, and analyze civic problems such as road damage, garbage issues, pipeline leaks, electricity failures, and public nuisance using location-based reporting and visual analytics.

Voice bridges the gap between citizens and authorities by transforming scattered complaints into organized, actionable insights.

---

## 🚀 Features

### 👤 User Panel
- Report public issues by selecting a **service type**
- Supported service types:
  - Road Issue  
  - Pipeline Issue  
  - Electricity Issue  
  - Garbage Issue  
  - Public Nuisance
- Location-based issue reporting

### 🛠 Admin Panel
- View all issues reported by users
- Update issue status:
  - Waiting
  - In Progress
  - Done
- Filter issues by **service type** and **location**
- Visual analytics using charts and graphs to identify problem-prone areas

---

## 🧑‍💻 Technologies Used
- Frontend: HTML, CSS, JavaScript
- Backend: Python (Flask)
- Database: SQLite / MySQL (based on configuration)
- Visualization: Chart.js
- Version Control: Git & GitHub

---

## 📂 Project Structure

    voice/
    │── app.py
    │── requirements.txt
    │── templates/
    │   ├── index.html
    │   ├── admin.html
    │── static/
    │   ├── css/
    │   ├── js/
    │── database/
    │   └── voice.db
    │── README.md

---

## ⚙️ Prerequisites
Make sure you have the following installed:
- Python 3.8 or above
- Git
- Web browser (Chrome / Firefox)

---

## ▶️ How to Run the Project Locally

### 1️⃣ Clone the Repository

    git clone https://github.com/gsd2503/voice.git
    cd voice

### 2️⃣ Create a Virtual Environment (Optional but Recommended)

    python3 -m venv venv
    source venv/bin/activate

### 3️⃣ Install Required Dependencies

    pip install -r requirements.txt

### 4️⃣ Run the Application

    python app.py

### 5️⃣ Open in Browser

    http://127.0.0.1:5000/

---

## 🔐 Admin Access
- Admin panel can be accessed through a predefined route (example: `/admin`)
- Admin credentials are configured in the backend (`app.py`)

---

## 📊 Usage Flow
1. Users submit issues by selecting service type and location.
2. Issues are stored with default status **Waiting**.
3. Admin reviews and updates issue status.
4. Charts and graphs update dynamically based on reported data.

---

## 📈 Future Enhancements
- User authentication
- Government department tagging
- Notification system
- Mobile app integration
- AI-based issue categorization

---

## 📜 License
This project is developed for academic purposes as part of a final-year project.

---

## ⭐ Acknowledgment
Special thanks to faculty and mentors for their guidance and support.
