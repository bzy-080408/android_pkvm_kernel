#ifdef CONFIG_MODULES
int __pkvm_init_module(unsigned long args_hva);
#else
static inline int __pkvm_init_module(unsigned long args_hva)
{
	return -EOPNOTSUPP;
}
#endif
