import collections
import logging
import re
from datetime import datetime
from django.http import HttpResponse
from openpyxl import Workbook
from openpyxl.styles import Font, Border, Side

import neo4j
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from neo4j import GraphDatabase
from project.settings import neo4jUser, neo4jPass, neo4jURI

from SlaGenerator.models import MACM, Asset, Relation, Protocol, Attribute, Attribute_value, Asset_Attribute_value, \
    Threat_Attribute_value, Threat_CIA, Threat_Stride, ThreatAgentQuestion, Reply, TAReplies_Question, TAReplyCategory,\
    ThreatAgentCategory, TACategoryAttribute, ThreatAgentAttribute, ThreatAgentRiskScores, StrideImpactRecord, Stride, \
    MACM_ThreatAgent, Threat_Protocol, Threat

neo4jUsername = neo4jUser
neo4jPassword = neo4jPass
neo4jUri = neo4jURI


def threat_agent_wizard(request, appId):
    context = {}
    # Generate question and related replies
    questions = ThreatAgentQuestion.objects.all()
    questions_replies = TAReplies_Question.objects.all()
    questions_replies_list = []
    for question in questions:
        replies = []
        question_replies_dict = {}
        for reply in questions_replies:
            if question == reply.question:
                replies.append(reply.reply.reply)
        question_replies_dict['question'] = question.question
        question_replies_dict['replies'] = replies
        questions_replies_list.append(question_replies_dict)
    context['questions_replies'] = questions_replies_list
    context['appId'] = appId
    return render(request, 'threat_agent_wizard.html', context)


@csrf_exempt
def threat_agent_generation(request, appId):
    print(appId)
    context = {}
    ThreatAgents = []
    ThreatAgentsPerAsset = []
    question = []
    # for category in ThreatAgentCategory.objects.all():  # inizializzo la lista finale a tutti i TA
    # ThreatAgents.append(category)

    for reply in request.POST:  # per ogni risposta al questionario
        ReplyObject = Reply.objects.filter(reply=reply).get()
        tareplycategories = TAReplyCategory.objects.filter(reply=ReplyObject)

        TAList = []
        for replycategory in tareplycategories.all():  # ogni categoria relativa ad una singola risposta
            # print(replycategory.reply.reply + " "+ replycategory.category.category)
            TAList.append(replycategory.category)
            question = TAReplies_Question.objects.filter(reply=ReplyObject)
        ThreatAgentsPerAsset.append((TAList, question))

    numQ3 = 0
    numQ4 = 0
    # conto il numero di risposte date per Q3 e Q4
    for ThreatAgentsList, question in ThreatAgentsPerAsset:  # per ogni risposta
        questionId = question.get().question.Qid
        if questionId == "Q3":
            numQ3 += 1
        if questionId == "Q4":
            numQ4 += 1

    ThreatAgentsList = []  # in case of empty list
    i = 0
    j = 0
    ThreatAgentsListTemp = []
    for ThreatAgentsList, question in ThreatAgentsPerAsset:  # per ogni risposta
        questionId = question.get().question.Qid
        if questionId == "Q1":
            ThreatAgents = ThreatAgentsList
        if questionId == "Q2":
            ThreatAgents = intersection(ThreatAgents, ThreatAgentsList)
        if questionId == "Q3":
            if i == 0:
                ThreatAgentsListTemp = ThreatAgentsList
            elif i < numQ3:
                ThreatAgentsList = union(ThreatAgentsList, ThreatAgentsListTemp)
                ThreatAgentsListTemp = ThreatAgentsList
            if i == numQ3 - 1:
                ThreatAgents = intersection(ThreatAgents, ThreatAgentsList)
            i = i + 1

        if questionId == "Q4":
            if j == 0:
                ThreatAgentsListTemp = ThreatAgentsList
                j = j + 1
            elif j == 1:
                ThreatAgentsListTemp = ThreatAgentsList
                j = j + 1
            elif j < numQ4:
                ThreatAgentsList = union(ThreatAgentsList, ThreatAgentsListTemp)
                ThreatAgentsListTemp = ThreatAgentsList

    ThreatAgents = intersection(ThreatAgents, ThreatAgentsList)
    ThreatAgentsWithInfo = {}
    for ta in ThreatAgents:
        ThreatAgentsWithInfo[ta] = list(TACategoryAttribute.objects.filter(category=ta))
        MACM_ThreatAgent.objects.get_or_create(
            app=MACM.objects.get(appId=appId),
            category=ta
        )

    context = {'ThreatAgents': ThreatAgentsWithInfo}
    context['appId'] = appId
    return render(request, 'threat_agent_generation.html', context=context)


def intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3


def union(lst1, lst2):
    lst3 = list(set(lst1 + lst2))
    return lst3


@csrf_exempt
def calculate_threat_agent_risks(request, appId):
    # TODO NEXT to continue, automatic threat agent risk calculation
    OWASP_Motive_TOT = 0
    OWASP_Size_TOT = 0
    OWASP_Opportunity_TOT = 0
    OWASP_Skill_TOT = 0
    somma_pesi = 1

    for category, risk_value in request.POST.items():
        TACategory = ThreatAgentCategory.objects.get(category=category)
        # per ogni categoria ottieni i Attribute relativi e calcola i 4 parametri owasp con le formule nella tesi.
        TACategoryAttributes = TACategoryAttribute.objects.filter(category=TACategory)
        OWASP_Motive = 0
        OWASP_Size = 0
        OWASP_Opportunity = 0
        OWASP_Skill = 0
        limits = 0
        intent = 0
        access = 0
        resources = 0
        visibility = 0
        skills = 0

        OWASP_Motives = []

        # scorro gli attributi di category
        for TACategoryAttributeVar in TACategoryAttributes:
            if TACategoryAttributeVar.attribute.attribute == 'Skills':
                skills = TACategoryAttributeVar.attribute.score
            if TACategoryAttributeVar.attribute.attribute == 'Resources':
                resources = TACategoryAttributeVar.attribute.score
            if TACategoryAttributeVar.attribute.attribute == 'Visibility':
                visibility = TACategoryAttributeVar.attribute.score
            if TACategoryAttributeVar.attribute.attribute == 'Limits':
                limits = TACategoryAttributeVar.attribute.score
            if TACategoryAttributeVar.attribute.attribute == 'Intent':
                intent = TACategoryAttributeVar.attribute.score
            if TACategoryAttributeVar.attribute.attribute == 'Access':
                access = TACategoryAttributeVar.attribute.score

        risk_valueNum = 0
        if risk_value == 'L':
            risk_valueNum = 1
        if risk_value == 'M':
            risk_valueNum = 2
        if risk_value == 'H':
            risk_valueNum = 3

        somma_pesi = somma_pesi + risk_valueNum
        OWASP_Motive = ((((intent / 2) + (limits / 4)) / 2) * 10)
        OWASP_Opportunity = ((((access / 2) + (resources / 6) + (visibility / 4)) / 3) * 10)
        OWASP_Size = (resources / 6) * 10
        OWASP_Skill = (skills / 4) * 10

        OWASP_Motive_TOT += (OWASP_Motive * risk_valueNum)
        OWASP_Opportunity_TOT += OWASP_Opportunity * risk_valueNum
        OWASP_Size_TOT += OWASP_Size * risk_valueNum
        OWASP_Skill_TOT += OWASP_Skill * risk_valueNum

    OWASP_Skill_TOT = int(round(OWASP_Skill_TOT / somma_pesi))
    OWASP_Motive_TOT = int(round(OWASP_Motive_TOT / somma_pesi))
    OWASP_Size_TOT = int(round(OWASP_Size_TOT / somma_pesi))
    OWASP_Opportunity_TOT = int(round(OWASP_Opportunity_TOT / somma_pesi))

    app = MACM.objects.get(appId=appId)

    ScoreAlreadyCreated = ThreatAgentRiskScores.objects.filter(app=app)
    if not ThreatAgentRiskScores.objects.filter(app=app).exists():
        obj = ThreatAgentRiskScores.objects.get_or_create(
            app=app,
            skill=OWASP_Skill_TOT,
            size=OWASP_Size_TOT,
            motive=OWASP_Motive_TOT,
            opportunity=OWASP_Opportunity_TOT)

    return render(request, 'stride_impact_evaluation.html', {"appId": appId})


@csrf_exempt
def stride_impact_evaluation_menu(request, appId):
    return render(request, 'stride_impact_evaluation.html', {"appId": appId})


@csrf_exempt
def threat_modeling_menu(request, appId):
    threats_list = threat_modeling(appId)
    return render(request, 'threat_modeling.html', {"threats": threats_list, "appId": appId})


@csrf_exempt
def stride_impact_evaluation(request, appId):
    threats_list = threat_modeling(appId)
    stride_impact_list = []
    app = MACM.objects.get(appId=appId)
    if not StrideImpactRecord.objects.filter(app=app).exists():
        save = False
        count = 0
        for info, value in request.POST.items():
            splittedInfo = info.split('_')
            impactValues = []
            stride = splittedInfo[0]
            impactInfo = splittedInfo[1]
            # print(stride+" "+impactInfo)
            strideCategory = 'nd'
            if stride == 'spoofing':
                strideCategory = 'Spoofing'
            if stride == 'tampering':
                strideCategory = 'Tampering'
            if stride == 'reputation':
                strideCategory = 'Reputation'
            if stride == 'informationdisclosure':
                strideCategory = 'Information Disclosure'
            if stride == 'dos':
                strideCategory = 'Denial Of Services'
            if stride == 'elevationofprivileges':
                strideCategory = 'Elevation of privileges'

            FinancialDamageValue = 0
            ReputationDamageValue = 0
            NonComplianceValue = 0
            PrivacyViolationValue = 0
            if impactInfo == 'noncompliance':
                NonComplianceString = 'Non Compliance'
                NonComplianceValue = value
                stride_impact_list.append((strideCategory, NonComplianceString, NonComplianceValue))
            if impactInfo == 'financialdamage':
                FinancialDamageValue = value
                FinancialDamageString = 'Financial Damage'
                stride_impact_list.append((strideCategory, FinancialDamageString, FinancialDamageValue))
            if impactInfo == 'reputationdamage':
                ReputationDamageValue = value
                ReputationDamageString = 'Reputation Damage'
                stride_impact_list.append((strideCategory, ReputationDamageString, ReputationDamageValue))
            if impactInfo == 'privacyviolation':
                PrivacyViolationValue = value
                PrivacyViolationString = 'Privacy Violation'
                stride_impact_list.append((strideCategory, PrivacyViolationString, PrivacyViolationValue))

            count += 1
            if count == 4:
                save = True
            if save:
                strideObject = Stride.objects.get(category=strideCategory)
                strideImpactRecord = StrideImpactRecord.objects.all().get_or_create(
                    app=app,
                    stride=strideObject,
                    financialdamage=FinancialDamageValue,
                    reputationdamage=ReputationDamageValue,
                    noncompliance=NonComplianceValue,
                    privacyviolation=PrivacyViolationValue)
                save = False
                count = 0

    return render(request, 'threat_modeling.html',
                  {"threats": threats_list, "appId": appId, 'stride_impact_list': stride_impact_list})


def apps_management(request):
    ordered_apps = []
    context = {}
    try:
        graphDriver = GraphDatabase.driver(uri=neo4jUri, auth=(neo4jUsername, neo4jPassword))
        session = graphDriver.session()
        nodes_string = session.run("match (node) return node")
        nodes = [record for record in nodes_string.data()]
        apps = {}
        for node in nodes:
            try:
                apps[node['node']['app_id']] = node['node']['application']
            except IndexError as ie:
                print('views:apps_management:apps[node]:IndexException' + ie)
            except Exception:
                print("Cannot parse graph with node " + str(node['node']))
            except BaseException:
                print('Unknown exception!')
        ordered_apps = collections.OrderedDict(sorted(apps.items()))
        # print(ordered_apps)
        for appId, application in ordered_apps.items():
            MACM_instance = MACM(appId=appId, application=application)
            MACMvalue = MACM.objects.all().filter(appId=appId, application=application)
            if not MACMvalue:
                MACM_instance.save()
            graphDriver.close()
        context = {
            'apps': ordered_apps
        }
    except neo4j.exceptions.ServiceUnavailable as error:
        print(error)
        context = {
            'error': error
        }
    return render(request, 'apps_management.html', context)


# TC do query to neo4j DB
def do_query(cipher_query):
    records = []
    try:
        graph = GraphDatabase.driver(uri=neo4jUri, auth=(neo4jUsername, neo4jPassword))
        session = graph.session()
        nodes_string = session.run(cipher_query)
        records = [record for record in nodes_string.data()]
        session.close()
    except IndexError as ie:
        print('views:do_query:GraphDB_query:IndexException' + ie)
    except Exception:
        print("views:do_query:Exception: " + str(cipher_query))
    except BaseException:
        print('views:do_query:Unknown exception!')

    return records


def get_graphNodesbyAppId(appId):
    nodes = do_query("MATCH (node { app_id:  \'" + str(appId) + "\' }) RETURN node,labels(node) as nodeType")
    return nodes


def get_graphProtRelbyAppId(appId):
    nodes = do_query("MATCH (client { app_id:  \'" + str(appId) + "\' }) -[relation:uses]->(server) \
                     WHERE relation.protocol IS NOT NULL \
                     RETURN client, relation.protocol, server;")
    return nodes


def get_assets_relation(appId, relation_type, asset_name):
    nodes = []
    if relation_type == 'connects':
        nodes.append(do_query("MATCH (s)-[r]->(t) WHERE EXISTS{(s{app_id: \"" + str(appId) + "\"})-[:" + relation_type + "]->({name: \"" + asset_name + "\"})} \
                     RETURN s as source, r as relation, t as target;"))
        # print(nodes)
    elif relation_type == 'hosts':
        nodes.extend(do_query("MATCH (source { app_id: \'" + str(appId) + "\'})-[relation: " + relation_type + "]->(target {name: \"" + asset_name + "\"}) \
                     RETURN source, relation, target;"))
        nodes.extend(do_query("MATCH (source { app_id: \'" + str(appId) + "\', name: \"" + asset_name + "\"})-[relation: " + relation_type + "]->(target) \
                     RETURN source, relation, target;"))
    elif relation_type == 'uses':
        # TODO improve protocol management in the following query
        nodes.extend(do_query("MATCH (source { app_id: \'" + str(appId) + "\'})-[relation: " + relation_type + "]->(target {name: \"" + asset_name + "\"}) \
                     RETURN source, relation, target;"))
        nodes.extend(do_query("MATCH (source { app_id: \'" + str(appId) + "\', name: \"" + asset_name + "\"})-[relation: " + relation_type + "]->(target) \
                     RETURN source, relation, target;"))

    # elif relation_type == 'provides':
    #     nodes = do_query("MATCH (source { app_id: \'" + str(appId) + "\' }) -[relation: " + relation_type + "]->(target) \
    #                  RETURN source, relation, target;")
    # elif relation_type == 'processes':
    #     nodes = do_query("MATCH (source { app_id: \'" + str(appId) + "\' }) -[relation: " + relation_type + "]->(target) \
    #                  RETURN source, relation, target;")
    else:
        logging.warning('relation type is unknown!')

    logging.debug(f'relation type= {relation_type}, nodes= {nodes}')
    return nodes


def get_assets_relation_all(appId, asset):
    nodes = []
    for n in get_assets_relation(appId, 'connects', asset.name)[0]:
        print(n)
        if n['target']['name'] != asset.name:
            asset_attribute_value = Asset_Attribute_value.objects.all().filter(asset_id=asset.id)
            if len(asset_attribute_value) > 0:
                threats_attribute_values = Threat_Attribute_value.objects.all().filter(
                    attribute_value_id=asset_attribute_value[0].attribute_value.id)
            else:
                threats_attribute_values = []

            if len(threats_attribute_values) > 0:
                for threats_attribute_value in threats_attribute_values:
                    print(threats_attribute_value.threat)
            nodes.append(n)
    nodes.extend(get_assets_relation(appId, 'hosts', asset.name))
    nodes.extend(get_assets_relation(appId, 'uses', asset.name))
    return nodes


def get_threat_list_from_role_relation(role, relations):
    threats = []
    a = Asset.objects.all().filter(name=relations[role]['name'])
    asset_attribute_value = Asset_Attribute_value.objects.all().filter(asset_id=a[0].id)
    for aav in asset_attribute_value:
        ts = Threat_Attribute_value.objects.all().filter(attribute_value_id=aav.attribute_value.id)
        for t in ts:
            print(t.threat)
            threats.append(t.threat)
    return threats


def get_threats_from_asset_relation(appId, asset, relations):
    threats = []
    for r in relations:
        rt = r['relation'][1]
        if rt == 'connects':
            print("---")
            print(rt)
            if r['target']['name'] != asset.name:
                print(r)
                threats.extend(get_threat_list_from_role_relation('target', r))
            print("---")
        elif rt == 'hosts':
            print("---")
            print(rt)
            if r['source']['name'] == asset.name:
                print('source')
                print(r)
                threats.extend(get_threat_list_from_role_relation('target', r))
            elif r['target']['name'] == asset.name:
                print('target')
                print(r)
                threats.extend(get_threat_list_from_role_relation('source', r))
            print("---")
        elif rt == 'uses':
            print("---")
            print(rt)
            if r['source']['name'] == asset.name:
                print(f"source: {asset.name}, target: {r['target']['name']}")
                threats.extend(get_threat_list_from_role_relation('target', r))
            elif r['target']['name'] == asset.name:
                print(f"target: {asset.name}, source: {r['source']['name']}")
                print(r)
                threats.extend(get_threat_list_from_role_relation('source', r))
            print("---")
        else:
            print("No Threats by relation") # change to log

    print(threats)
    return threats


# TC Properties selection
def get_graphPropertybyAppId(appId):
    properties = do_query("MATCH (client {app_id: \'" + str(appId) + "\'})-[relationship:uses]->(destination) \
        WHERE relationship.protocol IS NOT NULL \
        RETURN client, destination, relationship;")
    return properties


def macm_viewer(request, appId):
    return render(request, 'macm_viewer.html', {'appId': appId})


def get_conditions(conditions):
    out = []
    if conditions is not None and len(conditions) and conditions.isascii():
        dm = {'n': 0, 'p': 1, 'f': 2}
        match_result = re.match("^\[[npf],[npf],[npf]\]$", conditions)
        if match_result:
            vs = match_result.string[1:-1].split(',')
            out = [dm[vs[0]], dm[vs[1]], dm[vs[2]]]
    else:
        logging.error('conditions are not strings!')
    return out


@csrf_exempt
def risk_analysis(request, appId):
    app = MACM.objects.get(appId=appId)
    app_name = app.application
    selected_component_name = ''
    components_with_threats = []
    components = Asset.objects.filter(app=app)

    try:
        for rp in request.POST:
            if rp == 'dropdown':
                selected_component_name = request.POST['dropdown']
            elif rp == 'save':
                selected_component_name = request.POST['save']
                # TODO Save evaluation and factors
            else:
                selected_component_name = components[0].name
    except IndexError:
        logging.error('bad index POST request!')
    except ReferenceError:
        logging.error('bad reference POST request!')
    except ConnectionError:
        logging.error('connection error POST request!')
    except Exception:
        logging.exception('unknown exception POST request!')

    component_under_analysis = components[0]
    for component in components:
        if len(threat_modeling_per_assetFun(component.id)) != 0:
            if selected_component_name == component.name:
                components_with_threats.append((component, True))
                component_under_analysis = component
            else:
                components_with_threats.append((component, False))

    threats = threat_modeling_per_assetFun(component_under_analysis.id)

    ta_scores = ThreatAgentRiskScores.objects.filter(app=app)

    # ricerca ultimo risultato.
    if len(ta_scores) > 0:
        ta_time_max = ta_scores[0].updated_at
        last_score = ta_scores[0]
        for ta_score in ta_scores:
            if ta_score.updated_at > ta_time_max:
                last_score = ta_score
    else:
        # in case of empty set
        last_score = 0

    SIRecords = StrideImpactRecord.objects.filter(app=app)

    # TODO Deprecated
    # PreCondition = "[n,n,n]"
    # PostCondition = "[n,n,n]"
    # LossOfConfidentiality = 0
    # LossOfIntegrity = 0
    # LossOfAvailability = 0
    # LossOfCPostConditionValue = 0
    # LossOfIPostConditionValue = 0
    # LossOfAPostConditionValue = 0
    # LossOfCPreConditionValue = 0
    # LossOfIPreConditionValue = 0
    # LossOfAPreConditionValue = 0

    for threat in threats:
        # Remember threat from threat_modeling_per_assetFun()
        # threat => (threat_attribute_value.threat, strides_per_threat, affectedRequirements)
        pre_condition = str(threat[0].PreCondition)
        post_condition = str(threat[0].PostCondition)
        v_max = [0, 0, 0, 0]  # [financial, reputation, noncompliance, privacy]
        for SIRecord in SIRecords:
            for t_stride in threat[1]:
                if SIRecord.stride.category.lower() == t_stride.lower():
                    v_max[0] = max(v_max[0], SIRecord.financialdamage)
                    v_max[1] = max(v_max[1], SIRecord.reputationdamage)
                    v_max[2] = max(v_max[2], SIRecord.noncompliance)
                    v_max[3] = max(v_max[3], SIRecord.privacyviolation)
        threat[0].financial = v_max[0]
        threat[0].reputation = v_max[1]
        threat[0].noncompliance = v_max[2]
        threat[0].privacy = v_max[3]

                    # TODO Deprecated
                    # if maxFinancial < SIRecord.financialdamage:
                    #     maxFinancial = SIRecord.financialdamage
                    # if maxReputation < SIRecord.reputationdamage:
                    #     maxReputation = SIRecord.reputationdamage
                    # if maxnoncompliance < SIRecord.noncompliance:
                    #     maxnoncompliance = SIRecord.noncompliance
                    # if maxprivacy < SIRecord.privacyviolation:
                    #     maxprivacy = SIRecord.privacyviolation

        v_pre_cnd = get_conditions(pre_condition)
        v_post_cnd = get_conditions(post_condition)
        threat[0].lossofc = ((v_pre_cnd[0] + v_post_cnd[0]) * 3) + 1
        threat[0].lossofi = ((v_pre_cnd[1] + v_post_cnd[1]) * 3) + 1
        threat[0].lossofa = ((v_pre_cnd[2] + v_post_cnd[2]) * 3) + 1

        logging.debug(f'threat: [LoC: {threat[0].lossofc}, LoI: {threat[0].lossofi}, LoA: {threat[0].lossofa}]')

        # TODO Deprecated
        # try:
        #     PreCondition.replace("[", "")
        #     PreCondition.replace("]", "")
        #     PostCondition.replace("[", "")
        #     PostCondition.replace("]", "")
        #
        #     # splitto con le ,
        #     PreCondition = PreCondition.split(",")
        #     PostCondition = PostCondition.split(",")
        #
        #     if PreCondition[0] == 'n':
        #         LossOfCPreConditionValue = 0
        #     if PreCondition[0] == 'p':
        #         LossOfCPreConditionValue = 1
        #     if PreCondition[0] == 'f':
        #         LossOfCPreConditionValue = 2
        #
        #     if PostCondition[0] == 'n':
        #         LossOfCPostConditionValue = 0
        #     if PostCondition[0] == 'p':
        #         LossOfCPostConditionValue = 1
        #     if PostCondition[0] == 'f':
        #         LossOfCPostConditionValue = 2
        #
        #     LossOfConfidentiality = ((LossOfCPostConditionValue + LossOfCPreConditionValue) * 3) + 1
        #
        #     if PreCondition[1] == 'n':
        #         LossOfIPreConditionValue = 0
        #     if PreCondition[1] == 'p':
        #         LossOfIPreConditionValue = 1
        #     if PreCondition[1] == 'f':
        #         LossOfIPreConditionValue = 2
        #
        #     if PostCondition[1] == 'n':
        #         LossOfIPostConditionValue = 0
        #     if PostCondition[1] == 'p':
        #         LossOfIPostConditionValue = 1
        #     if PostCondition[1] == 'f':
        #         LossOfIPostConditionValue = 2
        #
        #     LossOfIntegrity = ((LossOfIPostConditionValue + LossOfIPreConditionValue) * 3) + 1
        #
        #     if PreCondition[2] == 'n':
        #         LossOfAPreConditionValue = 0
        #     if PreCondition[2] == 'p':
        #         LossOfAPreConditionValue = 1
        #     if PreCondition[2] == 'f':
        #         LossOfAPreConditionValue = 2
        #     if PostCondition[2] == 'n':
        #         LossOfAPostConditionValue = 0
        #     if PostCondition[2] == 'p':
        #         LossOfAPostConditionValue = 1
        #     if PostCondition[2] == 'f':
        #         LossOfAPostConditionValue = 2
        #
        #     LossOfAvailability = ((LossOfAPostConditionValue + LossOfAPreConditionValue) * 3) + 1
        #
        #     threat[0].lossofc = LossOfConfidentiality
        #     threat[0].lossofi = LossOfIntegrity
        #     threat[0].lossofa = LossOfAvailability
        #
        # except:
        #     print("iNFO MISSING")

        # TODO NEXT Separation between ThreatCatalogu and ThreatModel (actually missing)

    return render(request, 'risk_analysis.html',
                  {"appName": app_name, "ComponentName": selected_component_name, "threats": threats,
                   "components": components_with_threats, "ThreatAgentScores": last_score, "appId": appId})


def asset_management(request, appId):
    # save assets info in sqlite
    # nodes = Asset.objects.all().filter(app=MACM.objects.get(appId=appId))
    # metto nodes=None perchè così prende sempre fa neo4j (dovrei gestire la coerenza fra i due DB)
    nodes = None
    relations = []
    # connect to neo4j only if sqlite assets are empty (API are laggy)
    if not nodes:
        nodes = get_graphNodesbyAppId(appId)
        # TODO improve node management with an advanced query in the function do_query()
        for node in nodes:
            # print(node["node"]["name"]+" "+ node["node"]["type"])
            # print(node)

            asset = Asset.objects.all().get_or_create(app=MACM.objects.get(appId=appId),
                                                      name=node["node"]["name"])
            # mi salvo id sqlite in dizionario
            node['id'] = asset[0].id

            try:
                # vedo se il nome del componente è un attribute value
                # per il 5g andrebbero considerate le minacce sia di SERVICE.Web che di UE (ad esempio)
                Attribute_value_instance = Attribute_value.objects.get(attribute_value=node["node"]["type"])
                Asset_Attribute_value.objects.all().get_or_create(asset=asset[0],
                                                                  attribute_value=Attribute_value_instance)
                nodes = Asset_Attribute_value.objects.all().filter(app=MACM.objects.get(appId=appId))
            except:
                print()

    # save relation info in sqlite

    arches = get_graphProtRelbyAppId(appId)
    logging.debug(arches)
    logging.info("graph relations loaded successfully!")
    # TODO improve relation management with an advanced query in the function do_query()
    for arch in arches:
        p = Protocol.objects.all().filter(protocol=arch['relation.protocol'])
        c = Asset.objects.all().filter(name=arch['client']['name'], app=MACM.objects.get(appId=appId))
        s = Asset.objects.all().filter(name=arch['server']['name'], app=MACM.objects.get(appId=appId))
        if len(p) == 1 and len(c) == 1 and len(s) == 1:
            Relation.objects.all().get_or_create(protocol=p[0],
                                                 app=MACM.objects.get(appId=appId),
                                                 source=c[0],
                                                 target=s[0])
            relations.append((p[0].id, c[0].id, s[0].id, p[0].protocol, c[0].name, s[0].name))
        else:
            logging.warning(f'duplication! multiple objects are returned in prt= {p}, cli= {c}, srv= {s}, \
            it is expected only one')

    return render(request, 'asset_management.html', {
        'nodes': nodes,
        'relations': relations,
        'appId': appId
    })


def threat_modeling_per_asset(request, appId, assetId):
    asset = []
    threats = []
    try:
        asset = Asset.objects.all().filter(id=assetId)[0]
        asset_attribute_value = Asset_Attribute_value.objects.all().filter(asset_id=assetId)
        if len(asset_attribute_value) > 0:
            threats_attribute_values = Threat_Attribute_value.objects.all().filter(
                attribute_value_id=asset_attribute_value[0].attribute_value.id)
        else:
            threats_attribute_values = []
        for threat_attribute_value in threats_attribute_values:
            strides_per_threat = []
            affectedRequirements = []
            try:
                for stride in Threat_Stride.objects.all().filter(threat=threat_attribute_value.threat):
                    strides_per_threat.append(stride.stride.category)
                for requirement in Threat_CIA.objects.all().filter(threat=threat_attribute_value.threat):
                    affectedRequirements.append(requirement.cia.requirement)
            except:
                logging.error("Error in selecting additional threat info!")

            threats.append((threat_attribute_value.threat, strides_per_threat, affectedRequirements))
    except:
        logging.error("OutOfRange!")

    # Threat list per protocol
    all_relations = []
    relations_src = Relation.objects.all().filter(source=assetId)
    relations_trg = Relation.objects.all().filter(target=assetId)
    all_relations = relations_src | relations_trg
    logging.debug(f'all_relation: {all_relations}')
    if len(all_relations) > 0:
        for relation in all_relations:
            logging.debug(f"src= {relation.source.name}, trg= {relation.target.name}, prt= {relation.protocol.protocol}, src.id= {relation.source}")
            threat_per_protocol_list = get_threat_protocol(appId, relation)
            # TODO select only distinct threats, remove threat duplicates
            for t_pro in threat_per_protocol_list:
                strides_per_threat = []
                affectedRequirements = []
                try:
                    for stride in Threat_Stride.objects.all().filter(threat=t_pro.id):
                        strides_per_threat.append(stride.stride.category)
                    for requirement in Threat_CIA.objects.all().filter(threat=t_pro.id):
                        affectedRequirements.append(requirement.cia.requirement)
                except:
                    print("Error in selecting additional info")

                # TODO manage the case of asset with both source and target role.
                if asset.id == relation.source.id:
                    role = 'Client'
                elif asset.id == relation.target.id:
                    role = 'Server'
                else:
                    logging.warning('asset.id is none!')
                    role = 'none'
                logging.debug(f'({t_pro}, {strides_per_threat}, {affectedRequirements}, {role})')
                threats.append((t_pro, strides_per_threat, affectedRequirements, role))
    else:
        logging.info('threat list per protocol is empty, no relation found!')

    # Neighbouring
    neighbour_threats = get_threats_from_asset_relation(appId, asset, get_assets_relation_all(appId, asset))

    return render(request, 'threat_modeling_per_asset.html',
                  {'threats': threats, 'asset': asset, 'neighbour_threats': neighbour_threats})


def threat_modeling_per_assetFun(assetId):
    threats = []
    try:
        asset = Asset.objects.all().filter(id=assetId)[0]
        asset_attribute_value = Asset_Attribute_value.objects.all().filter(asset_id=assetId)
        threats_attribute_values = Threat_Attribute_value.objects.all().filter(
            attribute_value_id=asset_attribute_value[0].attribute_value.id)
        for threat_attribute_value in threats_attribute_values:
            strides_per_threat = []
            affectedRequirements = []
            try:
                for stride in Threat_Stride.objects.all().filter(threat=threat_attribute_value.threat):
                    strides_per_threat.append(stride.stride.category)
                for requirement in Threat_CIA.objects.all().filter(threat=threat_attribute_value.threat):
                    affectedRequirements.append(requirement.cia.requirement)
            except:
                print("Error in selecting additional info")

            threats.append((threat_attribute_value.threat, strides_per_threat, affectedRequirements))
    except:
        print("OutOfRange")
    return threats


def get_threat_protocol(app_id, relation):
    threat_protocols = []
    threat_protocols = Threat_Protocol.objects.all().filter(protocol_id=relation.protocol.id)
    logging.debug(threat_protocols)
    threats_protocol_per_asset = []
    for threat_protocol in threat_protocols:
        t = Threat.objects.all().filter(id=threat_protocol.threat_id)
        if t is not None:
            threats_protocol_per_asset.append(t[0])

    logging.debug(threats_protocol_per_asset)

    return threats_protocol_per_asset


def threat_modeling(appId):
    threats_list = []
    nodes = get_graphNodesbyAppId(appId)
    for node in nodes:
        asset = Asset.objects.all().filter(name=node["node"]["name"])[0]
        asset_attribute_value = Asset_Attribute_value.objects.all().filter(asset=asset)
        try:
            # print(asset.name + " " + asset_attribute_value[0].attribute_value.attribute_value)
            threats_attribute_values = Threat_Attribute_value.objects.all().filter(
                attribute_value=asset_attribute_value[0].attribute_value)
            for threat_attribute_value in threats_attribute_values:
                strides_per_threat = []
                affectedRequirements = []
                try:
                    # print(Threat_Stride.objects.all().filter(threat=threat_attribute_value.threat))
                    for stride in Threat_Stride.objects.all().filter(threat=threat_attribute_value.threat):
                        strides_per_threat.append(stride.stride.category)
                    for requirement in Threat_CIA.objects.all().filter(threat=threat_attribute_value.threat):
                        affectedRequirements.append(requirement.cia.requirement)
                    threats_list.append(
                        (threat_attribute_value.threat, strides_per_threat, affectedRequirements, asset.name,
                         threat_attribute_value.attribute_value))
                except:
                    print("Error in selecting additional info")
        except:
            print()
    return threats_list


# TC set_format
def set_format(worksheet, row_num, col_num, cell_val, fsize, fbold, fcol):
    cell = worksheet.cell(row=row_num, column=col_num)
    cell.value = cell_val
    cell.font = Font(name="Arial", size=fsize, bold=fbold, color=fcol)
    cell.border = Border(left=Side(border_style="thin", color='FF000000'),
                         right=Side(border_style="thin", color='FF000000'),
                         top=Side(border_style="thin", color='FF000000'),
                         bottom=Side(border_style="thin", color='FF000000'), )


def export_threat_modeling(request, appId):
    if request.method == "POST":

        # help: https://djangotricks.blogspot.com/2019/02/how-to-export-data-to-xlsx-files.html
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        )
        response['Content-Disposition'] = 'attachment; filename={date}-{name}-TM-report.xlsx'.format(
            date=datetime.now().strftime('%Y-%m-%d'),
            name=MACM.objects.get(appId=appId).application.replace(" ", "_")
        )
        workbook = Workbook()

        # Get active worksheet/tab
        worksheet = workbook.active
        worksheet.title = 'Threat_modeling_REPORT'
        columns = ['#', 'Threat Agent', 'Asset name', 'Asset type', 'Threat', 'CIA', 'STRIDE', 'Behaviour']
        row_num = 1

        # Assign the titles for each cell of the header
        for col_num, column_title in enumerate(columns, 1):
            set_format(worksheet, row_num, col_num, column_title, 12, True, 'FF0000')

        threats_list = threat_modeling(appId)
        ThreatAgents = MACM_ThreatAgent.objects.all().filter(app=MACM.objects.get(appId=appId))
        for ta in ThreatAgents:
            for threat in threats_list:
                row_num += 1
                stride = ""
                cia = ""
                for index, single in enumerate(threat[1]):
                    if not index == len(threat[1]) - 1:
                        stride += single + ", "
                    else:
                        stride += single

                for index, single in enumerate(threat[2]):
                    if not index == len(threat[1]) - 1:
                        cia += single + ", "
                    else:
                        cia += single

                # columns = ['Asset name', 'Asset type', 'Threat', 'Description', 'CIA', 'STRIDE']
                # print(threat[4].attribute_value)
                # Define the data for each cell in the row
                row = [
                    row_num - 1,
                    ta.category.category,
                    threat[3],
                    threat[4].attribute_value,
                    threat[0].name,
                    cia,
                    stride,
                    threat[0].description,
                ]

                # Assign the data for each cell of the row
                for col_num, cell_value in enumerate(row, 1):
                    set_format(worksheet, row_num, col_num, cell_value, 11, False, 'FF000000')

                    for col_num, cell_value in enumerate(row, 1):
                        set_format(worksheet, row_num, col_num, cell_value, 11, False, 'FF000000')
            # Per effettuare il resize delle celle in base a quella più grande
            dims = {}

            from openpyxl.styles import Alignment

            for row in worksheet.rows:
                for cell in row:
                    cell.alignment = Alignment(wrap_text=True)
                    if cell.value:
                        dims[cell.column_letter] = max((dims.get(cell.column_letter, 0), len(str(cell.value)))) + 0.07
            for col, value in dims.items():
                worksheet.column_dimensions[col].width = value

        workbook.save(response)

        return response
