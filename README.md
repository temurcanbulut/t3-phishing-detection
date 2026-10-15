# T3 Phishing Detection [ Web Application ]

This project is a web-based application designed to detect phishing attacks by analyzing URLs. The application calculates a phishing score based on various factors, such as SSL certificate status and domain age, to help determine whether a URL is malicious.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [How It Works](#how-it-works)
- [Contributing](#contributing)

## Features

- **Domain Validation**: Checks whether the domain format is valid.
- **Phishing Score Calculation**: Calculates a phishing score based on various criteria, such as SSL certificate status, domain age, and URL length.
- **SSL Certificate Information**: Retrieves SSL certificate details, including the issuing authority, validity period, and expiration date.
- **Domain Ranking**: Retrieves the global ranking of the domain using Alexa Rank.
- **HSTS Support Check**: Determines whether the domain supports HTTP Strict Transport Security (HSTS).
- **IP Address Check**: Detects whether the URL contains an IP address instead of a domain name.
- **Google Safe Browsing**: Checks if the domain is flagged as malicious by the Google Safe Browsing API.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/phishing-detection.git
    cd phishing-detection
    ```

2. **Create and activate a virtual environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Run the application**:
    ```bash
    python app.py
    ```

## Usage

Once the application is running, open your web browser and go to `http://127.0.0.1:5000/`. You can enter a domain, and the application will return a JSON response containing various details about the domain, including a phishing score.

## API Endpoints

### `GET /`

Renders the homepage where you can input a domain for analysis.

### `GET /check_domain`

Analyzes the provided domain and returns a JSON object containing the following details:
- **domain**: The domain being analyzed.
- **domain_age_days**: The age of the domain in days.
- **owner**: The name of the domain owner.
- **owner_email**: The email address of the domain owner.
- **domain_rank**: The global rank of the domain.
- **ssl_certificate_status**: Whether the domain has a valid SSL certificate.
- **issued_to**: The entity to whom the SSL certificate was issued.
- **issued_by**: The authority that issued the SSL certificate.
- **valid_from**: The start date of the SSL certificate.
- **valid_till**: The expiration date of the SSL certificate.
- **days_to_expiry**: The number of days until the SSL certificate expires.
- **hsts_support**: Whether the domain supports HSTS.
- **url_depth**: The depth of the URL path.
- **contains_ip**: Whether the URL contains an IP address.
- **google_safe_browsing_status**: Whether the domain is flagged by Google Safe Browsing.
- **score**: The calculated phishing score.

## How It Works

The application uses a series of techniques to evaluate the phishing risk of a given domain:

1. **Domain Validation**: Ensures the domain has a valid format.
2. **SSL Information**: Checks whether the domain has a valid SSL certificate and retrieves certificate details.
3. **Domain Ranking**: Fetches the global ranking of the domain from Alexa.
4. **HSTS Check**: Verifies if the domain supports HSTS.
5. **Google Safe Browsing**: Uses the Google Safe Browsing API to check if the domain is flagged as malicious.
6. **Phishing Score Calculation**: Combines the results of these checks to produce a phishing score.

## Contributing

We welcome contributions! Please send a pull request or open an issue to discuss ideas or suggestions.

![1](https://github.com/user-attachments/assets/a2cf71c6-5171-4284-9327-f89ebd3117c5)

Example usage video:
https://www.youtube.com/watch?v=6S9v_cZMzoo
