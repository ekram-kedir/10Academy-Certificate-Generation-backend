import json
import requests
from app import app

def test_create_certificate():
    url = 'http://localhost:3000/create-certificate'
    data = {
        'traineeName': 'John Doe',
        'course': 'Web3 Technologies',
        'completionDate': '2022-01-15',
    }

    response = requests.post(url, json=data)

    assert response.status_code == 200
    result = json.loads(response.text)
    assert result['success'] == True
    assert 'certificate' in result
    assert 'nftTransactionHash' in result['certificate']

# Additional tests can be added based on the functionalities you implement
