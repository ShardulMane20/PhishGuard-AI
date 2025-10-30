<div align="center">
  
# 🛡️ PhishGuard AI

### AI-Powered Phishing URL Detection System  
**Developed by [Shardul Mane](https://github.com/ShardulMane20), Neeraj Sharma & Shivam Gokhale**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3.2-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/ShardulMane20/PhishGuard-AI/graphs/commit-activity)

**[Live Demo](https://phishguard-ai.com)** • **[Report Bug](https://github.com/ShardulMane20/PhishGuard-AI/issues)** • **[Request Feature](https://github.com/ShardulMane20/PhishGuard-AI/issues)**

</div>

---

## 🎯 About

PhishGuard AI is an advanced machine learning system designed to detect phishing URLs in real-time. Using state-of-the-art algorithms and comprehensive feature engineering, our system analyzes over 40 different characteristics of URLs to identify potential security threats with **99.2% accuracy**.

### ✨ Key Features

- 🚀 **Real-Time Analysis**: Get results in under 100ms  
- 🎯 **High Accuracy**: 99.2% accuracy rate with minimal false positives  
- 🔍 **Comprehensive**: Analyzes 40+ URL features  
- 🌐 **Easy to Use**: Simple web interface and RESTful API  
- 📊 **Batch Processing**: Analyze up to 100 URLs simultaneously  
- 🔒 **Privacy-Focused**: No URL logging or data storage  

---

## 🛠️ Technology Stack

### Backend
- **Python 3.10+**: Core programming language  
- **Flask 3.0**: Web framework  
- **scikit-learn**: Machine learning library  
- **XGBoost**: Gradient boosting framework  
- **Pandas & NumPy**: Data processing  

### Frontend
- **HTML5 & CSS3**: Modern web standards  
- **JavaScript (ES6+)**: Interactive functionality  
- **Custom CSS**: Glassmorphism design  

### Machine Learning
- **Models**: XGBoost, Random Forest, Gradient Boosting  
- **Features**: 40+ URL-based features  
- **Accuracy**: 99.2%  

---

## 📥 Installation

### Prerequisites

- Python 3.10 or higher  
- pip package manager  

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/ShardulMane20/PhishGuard-AI.git
cd PhishGuard-AI

# 2. Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# 3. Install dependencies
pip install -r frontend/requirements.txt

# 4. Run the application
cd frontend
python app.py

# 5. Open browser
# Visit: http://localhost:5000
