# yaya-python-sdk
This is a Python SDK package for handling API integration on merchant application.

# Installation
To install the sdk to your python based application, add
```
yayawallet-python-sdk==VERSION
```
to the requirements.txt file on your python project. Then run 'pip install -r requirements.txt'.

# Environment
The sdk expects api credentials to be provided by the user. To set it up, you need to create a .env file and add the following environment variables:
```
YAYA_API_URL=https://yayawallet.com/api/en
YAYA_API_PATH=/api/en
YAYA_API_KEY=your_yayawallet_api_key
YAYA_API_SECRET=your_yayawallet_api_secret
```

You can find the last two credentials on https://yayawallet.com/en/profile/settings, after you logged in to your account on a browser.

# How to use?
This sdk provides functions that will call different apis available on YaYa's system. Here is how you can call ```getTransactionListByUser``` function:
```
from adrf.decorators import api_view
from rest_framework.response import Response
from yayawallet_python_sdk.api import transaction

@api_view(['GET'])
async def proxy_get_transaction_list_by_user(request):
    response = await transaction.get_transaction_list_by_user(None)
    return Response(response)
```

You can get the list of services available on ```yayawallet_python_sdk/api``` folder on this repo.