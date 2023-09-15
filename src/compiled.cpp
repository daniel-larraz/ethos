#include "type_checker.h"
#include "state.h"

namespace alfc {
  
std::string State::showCompiledFiles()
{
  return "";
}

void State::run_initialize()
{
}

Expr TypeChecker::run_getTypeInternal(ExprValue* hdType,
                                      const std::vector<ExprValue*>& args,
                                      std::ostream* out)
{
  return d_null;
}

Expr TypeChecker::run_evaluate(ExprValue* e, Ctx& ctx) { return d_null; }

ExprValue* TypeChecker::run_evaluateProgram(const std::vector<ExprValue*>& args,
                                            Ctx& ctx)
{
  return nullptr;
}

}
