package missing_hardening

import (
	"strconv"

	"github.com/threagile/threagile/model"
)

const raaLimit = 55
const raaLimitReduced = 40

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-hardening",
		Title: "Missing Hardening",
		Description: "Recursos técnicos com um valor de Atração Relativa do Atacante (RAA) de " + strconv.Itoa(raaLimit) + " % or mais alto deveria ser " +
			"explicitamente reforçado, levando em consideração as práticas recomendadas e os guias de proteção do fornecedor. ",
		Impact:     "Se esse risco permanecer inalterado, os invasores poderão atacar mais facilmente alvos de alto valor. ",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "System Hardening",
		Mitigation: "Tente aplicar todas as melhores práticas de proteção (como benchmarks CIS, recomendações OWASP, fornecedor " +
			"recomendações, DevSec Hardening Framework, DBSAT para bancos de dados Oracle e outros).",
		Check:    "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function: model.Operations,
		STRIDE:   model.Tampering,
		DetectionLogic: "Ativos técnicos no escopo com valores de RAA de " + strconv.Itoa(raaLimit) + " % or mais alto. " +
			"Geralmente, para destinos de alto valor, como armazenamentos de dados, servidores de aplicativos, provedores de identidade e sistemas ERP, esse limite é reduzido para " + strconv.Itoa(raaLimitReduced) + " %",
		RiskAssessment:             "A classificação de risco depende da sensibilidade dos dados processados ou armazenados no ativo técnico.",
		FalsePositives:             "Normalmente não há falsos positivos.",
		ModelFailurePossibleReason: false,
		CWE:                        16,
	}
}

func SupportedTags() []string {
	return []string{"tomcat"}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			if technicalAsset.RAA >= raaLimit || (technicalAsset.RAA >= raaLimitReduced &&
				(technicalAsset.Type == model.Datastore || technicalAsset.Technology == model.ApplicationServer || technicalAsset.Technology == model.IdentityProvider || technicalAsset.Technology == model.ERP)) {
				risks = append(risks, createRisk(technicalAsset))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Missing Hardening</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood:       model.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
