#pragma once

#include <memory>

namespace Utility
{

template <typename T>
class SingletonBase
{
public:
	template <typename... Args>
	static std::shared_ptr<T> get_instance(Args&&... args)
	{
		if (!_instance) [[unlikely]]
		{
			_instance = std::shared_ptr<T>(new T(std::forward<Args>(args)...));
		}
		return _instance;
	}

protected:
	SingletonBase() = default;
	virtual ~SingletonBase() = default;

private:
	SingletonBase(const SingletonBase&) = delete;
	SingletonBase& operator=(const SingletonBase&) = delete;

private:
	static std::shared_ptr<T> _instance;
};

// TODO: Initialize `_instance` inside `get_instance()`, not at declaration
template <typename T>
std::shared_ptr<T> SingletonBase<T>::_instance = nullptr;

}		 // namespace Utility
