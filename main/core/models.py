from django.db import models

# Create your models here.
    
class File(models.Model):
    filename = models.CharField(max_length=100)
    pdf = models.FileField(upload_to='media/files/', blank=True)
    audio = models.FileField(upload_to='media/files/', blank=True)
    video = models.FileField(upload_to='media/files/', blank=True)
    image = models.FileField(upload_to='media/files/', blank=True)
    description = models.TextField()
    num_downloads = models.PositiveBigIntegerField(default=0)
    num_shares = models.PositiveBigIntegerField(default=0)
    
    def __str__(self):
        return self.filename


