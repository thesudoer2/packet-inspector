#pragma once

#include <map>

#include "Session.h"
#include "Singleton.h"

#ifdef BE_VERBOSE
#define VERBOSE(x) x
#else
#define VERBOSE(x)
#endif

namespace Session {

class SessionCollection : public Utility::SingletonBase<SessionCollection> {
  friend Utility::SingletonBase<SessionCollection>;

public:
  using SessionContainer = std::map<SessionKey, std::shared_ptr<SessionBase>>;
  using SessionContainerIterator = SessionContainer::iterator;
  using SessionContainerConstIterator = SessionContainer::const_iterator;

public:
  std::pair<SessionContainerIterator, bool> addSessionPair(
      std::pair<SessionKey, std::shared_ptr<SessionBase>> session_pair);

  VERBOSE(void printSessions() const noexcept);
  VERBOSE(void printSession(const SessionKey &session_key) const noexcept);

private:
  SessionCollection() noexcept = default;

private:
  SessionContainer _active_sessions;
};

} // namespace Session
