from fastapi import APIRouter, Request, Depends
from sqlalchemy.orm import Session
from uuid import UUID

from ..schemas import schemas
from ..services import crud
from ..config import database, plaid

database.create_tables()

plaid_client = plaid.get_plaid_client()

router = APIRouter()

@router.get("/")
async def root():
    return {"message": "Server is running"}

# User signs up for the platform
@router.post("/platform/signup")
async def create_user(user: schemas.User):
    username = user.email
    password = user.password
    signup_result = crud.cognito_signup(username, password)
    return signup_result

# User logs into the platform
@router.post("/platform/login")
async def login_user(user: schemas.User):
    username = user.email
    password = user.password
    login_result = crud.cognito_login(username, password)
    return login_result

# Sign up for brokerage account
@router.post("/accounts/signup")
async def create_brokerage_account(account: schemas.AccountCreate, request: Request, db: Session = Depends(database.get_db)):
    account = crud.create_account(db=db, account=account, request=request)
    return account

# Get brokerage account
@router.get("/accounts/{account_id}", response_model=schemas.Account)
async def get_brokerage_account(account_id: UUID, request: Request, db: Session = Depends(database.get_db)):
    db_account = crud.get_account(db, account_id=account_id, request=request)
    return db_account

# Create ACH relationship using processor token
@router.post("/accounts/{identifier}/ach_relationship", response_model=schemas.Account)
async def create_ach_relationship(processor_token: schemas.ProcessorToken, identifier: str, request: Request, db: Session = Depends(database.get_db)):
   relationship = crud.create_ach_relationship(processor_token, identifier, db, request)
   return relationship

# Create Plaid link token
@router.post("/plaid/create_link_token")
def create_link_token(request: Request):
   link_token = crud.get_link_token(plaid_client, request)
   return link_token

# Get processor token from public token via Plaid
@router.post("/plaid/exchange_public_token")
async def exchange_token(plaid_response: schemas.PlaidExchangeInfo, request: Request):
   processor_token = crud.get_processor_token(plaid_response, plaid_client, request)
   return processor_token

# Create ACH relationship using processor token
@router.post("/accounts/{identifier}/ach_relationship", response_model=schemas.Account)
async def create_ach_relationship(processor_token: schemas.ProcessorToken, identifier: str, request: Request, db: Session = Depends(database.get_db)):
   relationship = crud.create_ach_relationship(processor_token, identifier, db, request)
   return relationship

# Transfer money using ACH relationship
@router.post("/accounts/{identifier}/transfer", response_model=schemas.Account)
async def create_funds_transfer(request_params: schemas.FundsTransferRequest, identifier: str, request: Request, db: Session = Depends(database.get_db)):
   transfer = crud.create_funds_transfer(request_params, identifier, db, request)
   return transfer

# Create a Journal between two accounts
@router.post("/journals")
async def create_journal(request_params: schemas.JournalParams, request: Request):
   journal = crud.create_journal(request_params, request)
   return journal

# Batch journal from one account to many
@router.post("/journals/batch")
async def create_batch_journal(request_params: schemas.BatchJournalParams, request: Request):
   batch_journal = crud.create_batch_journal(request_params, request)
   return batch_journal