package missing_waf

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-waf",
		Title: "Missing Web Application Firewall (WAF)",
		Description: "Para ter uma primeira linha de defesa de filtragem, as arquiteturas de segurança com serviços da Web ou aplicativos da Web devem incluir um WAF na frente deles. " +
			"Mesmo que um WAF não seja um substituto para a segurança (todos os componentes devem ser seguros, mesmo sem um WAF), ele adiciona outra camada de defesa ao geral " +
			"sistema atrasando alguns ataques e tendo um alerta de ataque mais fácil através dele.",
		Impact:     "Se esse risco não for mitigado, os invasores poderão aplicar testes de padrão de ataque padrão em grande velocidade, sem qualquer filtragem.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html",
		Action:     "Web Application Firewall (WAF)",
		Mitigation: "Considere colocar um Web Application Firewall (WAF) na frente dos serviços da web e / ou aplicativos da web. Para ambientes de nuvem, muitos provedores de nuvem oferecem " +
			"WAFs pré-configurados. Até mesmo proxies reversos podem ser aprimorados por um componente WAF por meio de plug-ins ModSecurity.",
		Check:          "Existe um Firewall de aplicativo da Web (WAF)?",
		Function:       model.Operations,
		STRIDE:         model.Tampering,
		DetectionLogic: "Serviços da Web e / ou aplicativos da Web dentro do escopo acessados através de um limite de confiança da rede sem um Firewall de aplicativo da Web (WAF) na frente deles.",
		RiskAssessment: "A classificação de risco depende da sensibilidade do próprio ativo técnico e dos ativos de dados processados e armazenados.",
		FalsePositives: "Os destinos acessíveis apenas por WAFs ou proxies reversos contendo um componente WAF (como ModSecurity) podem ser considerados " +
			"como falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope &&
			(technicalAsset.Technology.IsWebApplication() || technicalAsset.Technology.IsWebService()) {
			for _, incomingAccess := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				if incomingAccess.IsAcrossTrustBoundaryNetworkOnly() &&
					incomingAccess.Protocol.IsPotentialWebAccessProtocol() &&
					model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Technology != model.WAF {
					risks = append(risks, createRisk(technicalAsset))
					break
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Missing Web Application Firewall (WAF)</b> risk at <b>" + technicalAsset.Title + "</b>"
	likelihood := model.Unlikely
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
