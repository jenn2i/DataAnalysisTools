# Data Analysis Tools

A tool that helps analyze leaked data for security research and investigation purposes.
Analyze SQL dumps, CSV, and JSON files directly in your browser with built-in IP intelligence and email domain classification.

## Key Features

### 📊 Data Analysis Studio (React Web App)
- **Multi-Format Support**: Auto-parse SQL, CSV, JSON, JSONL files
- **Real-time Field Analysis**: One-click frequency, unique values, and statistics
- **IP Intelligence**: Auto-detect country/VPN/TOR/Proxy from 100K+ IP database
- **Timezone Analysis**: Estimate user location from UTC offset
- **Smart Conversion**: Unix timestamp → Date, Hex IP → Standard IP
- **Dynamic Filtering & Sorting**: Real-time search with multi-condition filters
- **CSV Export**: Instantly download analysis results

### 📧 Email Domain Analyzer (Python Script)

- **Anonymous Email Detection**: Auto-detect 10,000+ disposable email domains
- **Privacy Service Classification**: Identify ProtonMail, Tutanota, etc.
- **Large-Scale Processing**: Handle millions of emails via chunk-based streaming
- **Auto-Categorization**: Classify Public Portal / Anonymous Service / Company domains

## Quick Start

### Running the React App
```bash
# Install dependencies
npm install

# Start development server
npm start
```

## Project Structure
```
DataAnalysis/
├── src/
│   ├── DataAnalyzer.jsx       # Main React component
│   ├── ip_database.js          # IP intelligence DB (auto-generated)
│   └── email.csv               # Sample email data
├── ip_db.py                    # Excel → JS converter
├── email_analyzer.py           # Email domain classifier
└── README.md
```

## Screenshots

추가 예정

## Credits

- IP Intelligence: Self-collected database
- Disposable Email List: [disposable-email-domains](https://github.com/miketheman/disposable-email-domains)