package sql_nosql_injection

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "sql-nosql-injection",
		Title: "SQL/NoSQL-Injection",
		Description: "Quando um banco de dados é acessado por meio de protocolos de acesso ao banco de dados, podem surgir riscos de SQL / NoSQL-Injection. " +
			"A classificação de risco depende do próprio ativo técnico de sensibilidade e dos ativos de dados processados ou armazenados.",
		Impact:     "Se esse risco não for mitigado, os invasores podem modificar consultas SQL / NoSQL para roubar e modificar dados e, eventualmente, escalar ainda mais para uma penetração mais profunda no sistema por meio de execuções de código.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		Action:     "SQL/NoSQL-Injection Prevention",
		Mitigation: "Tente usar a vinculação de parâmetro para se proteger de vulnerabilidades de injeção. " +
			"Quando um produto de terceiros é usado em vez de um software desenvolvido sob medida, verifique se o produto aplica a atenuação adequada e garanta um nível de patch razoável.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Development,
		STRIDE:         model.Tampering,
		DetectionLogic: "Banco de dados acessado por meio de protocolos de acesso a banco de dados típicos por clientes dentro do escopo. ",
		RiskAssessment: "A classificação de risco depende da sensibilidade dos dados armazenados no banco de dados.",
		FalsePositives: "Os acessos ao banco de dados por meio de consultas que não consistem em partes controláveis pelo chamador podem ser considerados " +
			"como falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        89,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			if incomingFlow.Protocol.IsPotentialDatabaseAccessProtocol(true) && (technicalAsset.Technology == model.Database || technicalAsset.Technology == model.IdentityStoreDatabase) ||
				(incomingFlow.Protocol.IsPotentialDatabaseAccessProtocol(false)) {
				risks = append(risks, createRisk(technicalAsset, incomingFlow))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink) model.Risk {
	caller := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>SQL/NoSQL-Injection</b> risk at <b>" + caller.Title + "</b> against database <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
	}
	likelihood := model.VeryLikely
	if incomingFlow.Usage == model.DevOps {
		likelihood = model.Likely
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
