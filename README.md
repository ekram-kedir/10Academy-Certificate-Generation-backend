# 10Academy-Certificate-Generation-backend

# Overview

This backend application manages the issuance and distribution of NFT certificates on the Algorand blockchain. It supports role-based functionalities for staff and trainees, enabling secure and efficient NFT management.

# Technologies Used

Python
Flask
PostgreSQL
Algorand SDK
JWT (for authentication)

# Key Functionalities

User Management:
User registration and login with role-based authentication (staff/trainee)
Secure storage of user credentials and wallet information

NFT Asset Management:
Asset creation and configuration by staff users
Opt-in requests by trainee users to receive NFTs
Approval or denial of opt-in requests by staff users
Transfer of NFTs to approved recipients

API Endpoints:
Registration and login endpoints
Asset creation, opt-in, approval/denial, and transfer endpoints
Endpoints to view pending opt-in requests (staff) and request status (trainee)

Integration with Algorand:
Utilizes Algorand SDK for asset creation and transactions
Interacts with the Algorand network for secure NFT operations

# Setup and Usage

Install required dependencies: pip install -r requirements.txt
Configure Algorand node connection details in app.py
Create a PostgreSQL database with the specified schema
Run the application: python app.py