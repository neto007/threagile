package main

import (
	"fmt"
	"math/rand"

	"github.com/threagile/threagile/model"
)

// JUST A DUMMY TO HAVE AN ALTERNATIVE PLUGIN TO USE/TEST

// used from plugin caller:
func CalculateRAA() string {
	for techAssetID, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		techAsset.RAA = float64(rand.Intn(100))
		fmt.Println("Usando cálculo aleatório de RAA fictício (apenas para testar o uso de outros arquivos de objetos compartilhados como plug-ins)")
		model.ParsedModelRoot.TechnicalAssets[techAssetID] = techAsset
	}
	// return intro text (for reporting etc., can be short summary-like)
	return "Apenas uma implementação de algoritmo fictício para fins de demonstração de plugabilidade."
}
