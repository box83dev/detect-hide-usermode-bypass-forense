#pragma once
#include <string>
#include <vector>
#include <unhide/models.h>

namespace unhide {
namespace comparacao {

modelos::DivergenciaVisao compararDiretorio(const std::string &diretorio);
std::vector<modelos::DivergenciaVisao> compararVarios(const std::vector<std::string> &diretorios, int limite);

}
}
