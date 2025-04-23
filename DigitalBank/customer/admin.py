from django.contrib import admin
from customer.models import (Admin, Current, Customer, FixedDeposit, LoanApplication, LoanOfficer, Savings,
    Transaction,Branch,UserDocument,CreditScore,Manager)   

# Register your models here.
admin.site.register(Customer)
admin.site.register(Admin)
admin.site.register(LoanOfficer)
admin.site.register(Savings)
admin.site.register(Current)
admin.site.register(LoanApplication)
admin.site.register(Transaction)
admin.site.register(FixedDeposit)
admin.site.register(Branch)
admin.site.register(UserDocument)
admin.site.register(CreditScore)
admin.site.register(Manager)



