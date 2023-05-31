from django.db import models

# Create your models here.

class Feed(models.Model):
    file = models.FileField()
    
