package ldap_injection

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "ldap-injection",
		Title: "LDAP-Injection",
		Description: "Quando um servidor LDAP é acessado, podem surgir riscos de injeção de LDAP. " +
			"A classificação de risco depende da sensibilidade do próprio servidor LDAP e dos ativos de dados processados ou armazenados.",
		Impact:     "Se esse risco permanecer inalterado, os invasores podem modificar as consultas LDAP e acessar mais dados do servidor LDAP do que o permitido.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
		Action:     "LDAP-Injection Prevention",
		Mitigation: "Tente usar bibliotecas que codificam corretamente os metacaracteres LDAP em pesquisas e consultas para acessar " +
			"o servidor LDAP para ficar protegido contra vulnerabilidades de injeção de LDAP. " +
			"Quando um produto de terceiros é usado em vez de um software desenvolvido sob medida, verifique se o produto aplica a atenuação adequada e garanta um nível de patch razoável.",
		Check:          "As recomendações da folha de dicas vinculada e do capítulo ASVS referenciado são aplicadas ?",
		Function:       model.Development,
		STRIDE:         model.Tampering,
		DetectionLogic: "Clientes dentro do escopo acessando servidores LDAP por meio de protocolos de acesso LDAP típicos.",
		RiskAssessment: "A classificação de risco depende da sensibilidade do próprio servidor LDAP e dos ativos de dados processados ou armazenados.",
		FalsePositives: "As consultas do servidor LDAP por valores de pesquisa que não consistem em partes controláveis pelo chamador podem ser consideradas " +
			"como falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        90,
	}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			if incomingFlow.Protocol == model.LDAP || incomingFlow.Protocol == model.LDAPS {
				likelihood := model.Likely
				if incomingFlow.Usage == model.DevOps {
					likelihood = model.Unlikely
				}
				risks = append(risks, createRisk(technicalAsset, incomingFlow, likelihood))
			}
		}
	}
	return risks
}

func SupportedTags() []string {
	return []string{}
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink, likelihood model.RiskExploitationLikelihood) model.Risk {
	caller := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>LDAP-Injection</b> risk at <b>" + caller.Title + "</b> against LDAP server <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           model.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
