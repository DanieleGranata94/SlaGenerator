from django.db import models

# Create your models here.


class MACM(models.Model):
    appId = models.IntegerField(null=True)
    application = models.CharField(max_length=100)






class Asset(models.Model):
    name = models.CharField(max_length=100)
    app = models.ForeignKey(MACM, on_delete=models.CASCADE)

class Protocol(models.Model):
    protocol = models.CharField(max_length=100)

class Stride(models.Model):
    category = models.CharField(max_length=100)

class CIA(models.Model):
    requirement = models.CharField(max_length=100)

class Threat(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500, null=True)
    source = models.CharField(max_length=500, null=True)
    PreCondition= models.CharField(max_length=500, null=True)
    PostCondition= models.CharField(max_length=500, null=True)
    owasp_ease_of_discovery = models.IntegerField(null=True)
    owasp_ease_of_exploit = models.IntegerField(null=True)
    owasp_intrusion_detection = models.IntegerField(null=True)
    owasp_awareness = models.IntegerField(null=True)
    owasp_loss_of_confidentiality = models.IntegerField(null=True)
    owasp_loss_of_integrity = models.IntegerField(null=True)
    owasp_loss_of_availability = models.IntegerField(null=True)
    owasp_loss_of_accountability = models.IntegerField(null=True)
    threat_family = models.CharField(max_length=500, null=True)
    Compromised = models.CharField(max_length=100,default="self", null=True)

class Control(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=1000, null=True)
    source = models.CharField(max_length=1000, null=True)

class ThreatAgentQuestion(models.Model):
    Qid= models.CharField(max_length=500,null=True)
    question = models.CharField(max_length=500)

class Reply(models.Model):
    reply = models.CharField(max_length=500)
    multiple= models.BooleanField(default=False)

class TAReplies_Question(models.Model):
    reply = models.ForeignKey(Reply, on_delete=models.CASCADE,null=True)
    question = models.ForeignKey(ThreatAgentQuestion, on_delete=models.CASCADE,null=True)


class Attribute(models.Model):
    attribute_name = models.CharField(max_length=100)

class Attribute_value(models.Model):
    attribute_value = models.CharField(max_length=100, null=True)
    description = models.CharField(max_length=100, null=True)
    attribute = models.ForeignKey(Attribute, on_delete=models.CASCADE,null=True)


class Asset_Attribute_value(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    attribute_value = models.ForeignKey(Attribute_value, on_delete=models.CASCADE,null=True)


class Threat_Attribute_value(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE,null=True)
    attribute_value = models.ForeignKey(Attribute_value, on_delete=models.CASCADE,null=True)
    behavior = models.CharField(max_length=100, null=True)

class Subthreat_Mapping(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE,related_name="threat")
    sub_threat = models.ForeignKey(Threat, on_delete=models.CASCADE,related_name="subthreat")
    relation_type = models.CharField(max_length=100)

class Threat_Control(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)
    control = models.ForeignKey(Control, on_delete=models.CASCADE)

class Subcontrol_Mapping(models.Model):
    control = models.ForeignKey(Control, on_delete=models.CASCADE,related_name="control")
    sub_control = models.ForeignKey(Control, on_delete=models.CASCADE,related_name="subcontrol")
    relation_type = models.CharField(max_length=100)

class Threat_Protocol(models.Model):
    protocol = models.ForeignKey(Protocol, on_delete=models.CASCADE)
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)

class Threat_Stride(models.Model):
    stride = models.ForeignKey(Stride, on_delete=models.CASCADE)
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)

class Threat_CIA(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE, null=True)
    cia = models.ForeignKey(CIA, on_delete=models.CASCADE, null=True)


class Relation(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, null=True)
    protocol = models.ForeignKey(Protocol, on_delete=models.CASCADE, null=True)
    app = models.ForeignKey(MACM, on_delete=models.CASCADE, null=True)
    relation_type = models.CharField(max_length=100, null=True)
    role = models.CharField(max_length=100, null=True)



class ThreatAgentCategory(models.Model):
    category = models.CharField(max_length=100,null=True)
    description = models.CharField(max_length=500,null=True)
    common_actions = models.CharField(max_length=500,null=True)

class ThreatAgentAttribute(models.Model):
    attribute = models.CharField(max_length=100,null=True)
    attribute_value = models.CharField(max_length=100,null=True)
    description = models.CharField(max_length=500,null=True)
    score = models.IntegerField(null=True)

class TACategoryAttribute(models.Model):
    category = models.ForeignKey(ThreatAgentCategory, on_delete=models.CASCADE, null=True)
    attribute = models.ForeignKey(ThreatAgentAttribute, on_delete=models.CASCADE, null=True)

class TAReplyCategory(models.Model):
    reply = models.ForeignKey(Reply, on_delete=models.CASCADE, null=True)
    category = models.ForeignKey(ThreatAgentCategory, on_delete=models.CASCADE, null=True)

class ThreatAgentRiskScores(models.Model):
    app = models.ForeignKey(MACM, on_delete=models.CASCADE)
    skill = models.IntegerField()
    size = models.IntegerField()
    motive = models.IntegerField()
    opportunity = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

class StrideImpactRecord(models.Model):
    app = models.ForeignKey(MACM, on_delete=models.CASCADE,null=True)
    stride = models.ForeignKey(Stride, on_delete=models.CASCADE,null=True)
    financialdamage = models.IntegerField(null=True)
    reputationdamage = models.IntegerField(null=True)
    noncompliance = models.IntegerField(null=True)
    privacyviolation = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

class MACM_ThreatAgent(models.Model):
    app = models.ForeignKey(MACM, on_delete=models.CASCADE)
    category = models.ForeignKey(ThreatAgentCategory, on_delete=models.CASCADE, null=True)



