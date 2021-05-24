Neste diretório se encontram os resultados do tempo de excução de cada aplicação, que foram colocados em um notebook python para calcular a média e desvio padrão.

Os resultados foram obtidos executando cada aplicação 10x em uma máquina com as seguintes especificações.
* OS: Ubuntu 18.04
* CPU: Intel Core i7 7700HQ
* RAM: DDR4 16GB (2x8GB) @ 2400MHz
* BIOS: X580VD.317
* Storage: 256GB M.2 SSD
* Versão do driver Intel SGX: a partir do repositório apt https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main
    - libsgx-enclave-common 2.13.103.1-bionic1
    - libsgx-enclave-common-dev 2.13.103.1-bionic1
* Versão do sgx-dcap:
    - https://download.01.org/intel-sgx/sgx-dcap/1.10/linux/distro/ubuntu18.04-server/
* Versão do Open Enclave: from apt
    open-enclave 0.15.0
* Versão do Madagascar: 3.1.1
* Compilador usado: gcc v7.5.0
