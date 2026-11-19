/******************************************************************************
 * This file is part of the ethos project.
 * See COPYING for licensing information.
 ******************************************************************************/
#ifndef PLUGIN_RUST_META_REDUCE_H
#define PLUGIN_RUST_META_REDUCE_H

#include "../meta_reduce_plugin.h"

namespace ethos {

/**
 * Emit a standalone, parser-free Rust proof checker. Structural desugaring
 * supplies calculus-specific typing and command invocation. Builtin operators
 * are compiled to the native Rust runtime instead of their EO implementations.
 */
class RustMetaReduce : public MetaReducePlugin
{
 public:
  explicit RustMetaReduce(State& s);
  void defineProgram(const Expr& v, const Expr& prog) override;
  void define(const std::string& name, const Expr& e) override;
  bool echo(const std::string& msg) override;
  void finalize() override;

 private:
  struct Program
  {
    Expr symbol;
    Expr body;
    bool isDefine;
  };
  struct Constructor
  {
    size_t arity;
  };
  enum class CacheKind
  {
    NONE,
    EO_TYPE,
    SMT_TYPE,
    PROGRAM
  };
  class Emitter;
  bool isBuiltinMetaSymbol(const std::string& name) const override;
  void finalizeDecl(const Expr& e) override;
  std::set<std::string> reachable(
      const std::set<std::string>& without = {}) const;
  void selectCaches(const std::set<std::string>& names);
  /** Whether a constructor is a user symbol, not an embedding or meta one. */
  static bool isUserConstructor(const std::string& name);
  std::string schema() const;
  /** The constructors by name, for the runtime's front part. */
  std::string constructorNames() const;
  /**
   * The number that stands for `text` in the calls of generated code: a
   * name or a constant the runtime is given only to read or to report.
   */
  size_t nativeText(const std::string& text);
  std::vector<std::string> d_nativeTexts;
  /** `Some(Constructor::X)` for a constructor of the signature, else `None`. */
  std::string constructorOption(const std::string& name) const;
  /** A runtime template with each `@ctor:NAME@` replaced by that. */
  std::string expandConstructors(std::string text) const;
  std::string emitProgram(const std::string& name, const Program& p);
  /** The name logos's Lean has for a program or a constructor. */
  static std::string leanName(const std::string& name);
  /**
   * The proof about a program's functions, for Lean (see `leanProofs`):
   * the script of each case, or why there is none.
   */
  struct LeanProof
  {
    struct Case
    {
      std::string unfolds;
      std::vector<std::string> lines;
    };
    std::string name;
    size_t nargs = 0;
    /** The arguments the body tests for the stuck term, in order. */
    std::vector<size_t> stuck;
    std::vector<Case> cases;
    bool loop = false;
    /** The number of its cache of results, or empty. */
    std::string cache;
    std::set<std::string> calls;
    std::string why;
  };
  std::vector<LeanProof> d_leanProofs;
  /** The programs that logos's Lean has a function for. */
  std::set<std::string> d_leanHas;
  /** The Lean file of the proofs, and the table of what has none. */
  void leanProofs(size_t numParts) const;
  void output(const std::string& file, const std::string& text) const;
  static std::string ident(const std::string& name);
  static std::string quote(const std::string& text);
  static Kind builtin(const std::string& name);
  std::map<std::string, Constructor> d_constructors;
  std::vector<std::string> d_constructorOrder;
  std::map<std::string, Program> d_programs;
  std::set<std::string> d_leftAssoc;
  std::map<std::string, CacheKind> d_cacheKinds;
  std::map<std::string, size_t> d_programIds;
};

}  // namespace ethos
#endif
