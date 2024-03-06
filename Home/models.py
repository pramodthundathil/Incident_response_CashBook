from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import localtime
import bcrypt


class IncomeSource(models.Model):
	user = models.ForeignKey(to = User,on_delete=models.CASCADE)
	source = models.CharField(max_length = 256)
	created_at = models.DateTimeField(default=localtime)

	def __str__(self):
		return str(self.user) + self.source

	class Meta:
		verbose_name_plural = 'Income Sources'

class Income(models.Model):
	user = models.ForeignKey(User,on_delete=models.CASCADE, null=True)
	amount = models.FloatField()
	date = models.DateField(default = localtime)
	description = models.TextField()
	source = models.CharField(max_length = 255)
	created_at = models.DateTimeField(default=localtime)
	

class ExpenseCategory(models.Model):
	user = models.ForeignKey(User,on_delete=models.CASCADE)
	name = models.CharField(max_length = 256)
	created_at = models.DateTimeField(default=localtime)
	
	def __str__(self):
		return str(self.user) + self.name

	class Meta:
		verbose_name_plural = 'Expense Categories'

class Expense(models.Model):
	user = models.ForeignKey(User,on_delete=models.CASCADE,null=True)
	amount = models.FloatField()
	date = models.DateField(default = localtime)
	description = models.TextField()
	category = models.CharField(max_length = 255)
	created_at = models.DateTimeField(default=localtime)
	

class CustomeUserModel(models.Model):
	login_attempt = models.PositiveIntegerField()
	user = models.OneToOneField(User,on_delete = models.CASCADE)
	
class IncidentLogs(models.Model):
	user = models.ForeignKey(User,on_delete = models.CASCADE)
	date = models.DateTimeField(auto_now_add = True)
	incident = models.CharField(max_length = 255)
	ipaddress = models.CharField(max_length = 255)
	




class CustomUser(models.Model):

    active = models.BooleanField(default = True)
    encrypted_password = models.CharField(max_length=128)

    def set_password(self, raw_password):
        # Generate a salt and hash the password using bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(raw_password.encode('utf-8'), salt)
        self.encrypted_password = hashed_password.decode('utf-8')

    def check_encrypted_password(self, raw_password):
        # Check if the hashed password matches the provided raw password
        return bcrypt.checkpw(raw_password.encode('utf-8'), self.encrypted_password.encode('utf-8'))
	
    user  = models.OneToOneField(User,on_delete = models.CASCADE)


class ApppasswordAttempt(models.Model):
	passwordattempt = models.PositiveIntegerField()
	custome = models.OneToOneField(CustomUser,on_delete = models.CASCADE)
    # user  = models.ForeignKey(User,on_delete = models.CASCADE)





	

