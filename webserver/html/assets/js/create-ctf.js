import {messageManager, apiClient} from './utils.js';

class CTFCreator {
    constructor() {
        this.vms = [];
        this.subnets = [];
        this.flags = [];
        this.hints = [];
        this.availableOVAs = [];
        this.config = null;

        this.selectedVM = null;
        this.selectedSubnet = null;
        this.selectedFlag = null;
        this.selectedHint = null;

        this.loadConfig().then(() => {
            this.initElements();
            this.initEventListeners();
            this.fetchAvailableOVAs();
            this.setupImageUpload();
            this.updateLayout();
        });
    }

    async loadConfig() {
        try {
            const response = await fetch('/config/general.config.json');
            const config = await response.json();
            this.config = config.ctf;

            this.config.CTF_NAME_REGEX = new RegExp(this.config.CTF_NAME_REGEX);
            this.config.VM_SUBNET_NAME_REGEX = new RegExp(this.config.VM_SUBNET_NAME_REGEX);
            this.config.DOMAIN_REGEX = new RegExp(this.config.DOMAIN_REGEX);
        } catch (error) {
            console.error('Failed to load config:', error);
        }
    }

    initElements() {

        this.tabGeneral = document.getElementById('tab-general');
        this.tabAdvanced = document.getElementById('tab-advanced');
        this.tabGeneralContent = document.getElementById('tab-general-content');
        this.tabAdvancedContent = document.getElementById('tab-advanced-content');


        this.tabVM = document.getElementById('tab-vm');
        this.tabSubnet = document.getElementById('tab-subnet');
        this.tabFlag = document.getElementById('tab-flag');
        this.tabHint = document.getElementById('tab-hint');


        this.vmInput = document.getElementById('vm-input');
        this.subnetInput = document.getElementById('subnet-input');
        this.flagInput = document.getElementById('flag-input');
        this.hintInput = document.getElementById('hint-input');


        this.vmForm = document.getElementById('vm-form');
        this.subnetForm = document.getElementById('subnet-form');
        this.flagForm = document.getElementById('flag-form');
        this.hintForm = document.getElementById('hint-form');


        this.ctfForm = {
            name: document.getElementById('ctf-name'),
            description: document.getElementById('ctf-description'),
            category: document.getElementById('ctf-category'),
            difficulty: document.getElementById('ctf-difficulty'),
            hint: document.getElementById('ctf-hint'),
            solution: document.getElementById('ctf-solution'),
            image: document.getElementById('ctf-image-preview')
        };


        this.vmIconsContainer = document.getElementById('vm-icons');
        this.subnetRegionsContainer = document.getElementById('subnet-regions');
        this.subnetVMsSelect = document.getElementById('subnet-vms');
        this.flagsList = document.getElementById('flags-list');
        this.hintsList = document.getElementById('hints-list');


        this.flagSubmitButton = this.flagForm.querySelector('button[type="submit"]');
        this.hintSubmitButton = this.hintForm.querySelector('button[type="submit"]');
        this.ctfSubmitButton = document.getElementById('submit-ctf');
        this.vmSubmitButton = this.vmForm.querySelector('button[type="submit"]');
        this.subnetSubmitButton = this.subnetForm.querySelector('button[type="submit"]');


        this.ovaDropdown = document.getElementById('vm-ova');


        [this.vmForm, this.subnetForm, this.flagForm, this.hintForm].forEach(form => {
            form.setAttribute('novalidate', '');
        });
    }

    initEventListeners() {

        this.tabGeneral.addEventListener('click', () => this.switchGeneralTab(this.tabGeneral));
        this.tabAdvanced.addEventListener('click', () => this.switchGeneralTab(this.tabAdvanced));


        this.tabVM.addEventListener('click', () => this.switchTab(this.tabVM, this.vmInput));
        this.tabSubnet.addEventListener('click', () => this.switchTab(this.tabSubnet, this.subnetInput));
        this.tabFlag.addEventListener('click', () => this.switchTab(this.tabFlag, this.flagInput));
        this.tabHint.addEventListener('click', () => this.switchTab(this.tabHint, this.hintInput));


        this.vmForm.addEventListener('submit', (e) => this.handleVMFormSubmit(e));
        this.subnetForm.addEventListener('submit', (e) => this.handleSubnetFormSubmit(e));
        this.flagForm.addEventListener('submit', (e) => this.handleFlagFormSubmit(e));
        this.hintForm.addEventListener('submit', (e) => this.handleHintFormSubmit(e));
        this.ctfSubmitButton.addEventListener('click', () => this.handleCTFSubmit());
    }


    switchTab(activeTab, activeSection) {
        [this.tabVM, this.tabSubnet, this.tabFlag, this.tabHint].forEach(tab => tab.classList.remove('active'));
        [this.vmInput, this.subnetInput, this.flagInput, this.hintInput].forEach(section => section.classList.remove('active'));

        activeTab.classList.add('active');
        activeSection.classList.add('active');
        this.clearSelection();
        this.resetForms();
    }

    switchGeneralTab(activeTab) {
        [this.tabGeneral, this.tabAdvanced].forEach(tab => tab.classList.remove('active'));
        [this.tabGeneralContent, this.tabAdvancedContent].forEach(content => content.classList.add('hidden'));

        switch (activeTab) {
            case this.tabGeneral:
                this.tabGeneral.classList.add('active');
                this.tabGeneralContent.classList.remove('hidden');
                break;

            case this.tabAdvanced:
                this.tabAdvanced.classList.add('active');
                this.tabAdvancedContent.classList.remove('hidden');
                break;

            default:
                console.warn('Unknown tab:', activeTab);
                break;
        }
    }


    showError(message, fields = []) {
        messageManager.showError(message);

        fields.forEach(field => {
            const element = document.querySelector(`[name="${field}"]`);
            if (element) {
                element.classList.add('error-field');
                element.focus();

                if (fields[0] === field) {
                    element.scrollIntoView({behavior: 'smooth', block: 'center'});
                }

                const removeHighlight = () => {
                    element.classList.remove('error-field');
                    element.removeEventListener('input', removeHighlight);
                    element.removeEventListener('change', removeHighlight);
                };
                element.addEventListener('input', removeHighlight);
                element.addEventListener('change', removeHighlight);
            }
        });
    }


    async handleVMFormSubmit(e) {
        e.preventDefault();
        document.querySelectorAll('.error-field').forEach(el => el.classList.remove('error-field'));

        if (!this.validateVMForm()) return;

        if (this.selectedVM) {

            this.selectedVM.name = this.vmForm['vm-name'].value;
            this.selectedVM.ova_id = this.vmForm['vm-ova'].value;
            this.selectedVM.cores = this.vmForm['vm-cores'].value;
            this.selectedVM.ram = this.vmForm['vm-ram'].value;
            this.selectedVM.ip = this.vmForm['vm-ip'].value;

            this.updateVMIcon(this.selectedVM);
            this.updateSubnetVMsDropdown();

            document.querySelectorAll('.subnet-region').forEach(region => {
                const subnetId = region.getAttribute('data-id');
                const subnet = this.subnets.find(s => s.id === subnetId);
                if (subnet && subnet.attachedVMs.includes(this.selectedVM.id)) {
                    this.updateSubnetVMs(region, subnet.attachedVMs);
                }
            });

            this.vmSubmitButton.textContent = 'Add VM';
            this.selectedVM = null;
        } else {

            const selectedOVA = this.availableOVAs.find(ova => ova.id == this.vmForm['vm-ova'].value);

            if (!selectedOVA) {
                this.showError('Invalid OVA selection', ['vm-ova']);
                return;
            }

            const vm = {
                name: this.vmForm['vm-name'].value,
                ova_id: this.vmForm['vm-ova'].value,
                ova_name: selectedOVA.name,
                cores: this.vmForm['vm-cores'].value,
                ram: this.vmForm['vm-ram'].value,
                ip: this.vmForm['vm-ip'].value,
                id: this.generateId()
            };
            this.vms.push(vm);
            this.createVMIcon(vm);
        }

        this.vmForm.reset();
    }


    async handleSubnetFormSubmit(e) {
        e.preventDefault();
        document.querySelectorAll('.error-field').forEach(el => el.classList.remove('error-field'));

        if (!this.validateSubnetForm()) return;

        if (this.selectedSubnet) {

            this.selectedSubnet.name = this.subnetForm['subnet-name'].value;
            this.selectedSubnet.dmz = this.subnetForm['subnet-dmz'].checked;
            this.selectedSubnet.accessible = this.subnetForm['subnet-accessible'].checked;

            this.updateSubnetRegion(this.selectedSubnet);
            this.subnetSubmitButton.textContent = 'Add Subnet';
            this.clearSelection();
            this.selectedSubnet = null;
        } else {

            const subnet = {
                name: this.subnetForm['subnet-name'].value,
                dmz: this.subnetForm['subnet-dmz'].checked,
                accessible: this.subnetForm['subnet-accessible'].checked,
                attachedVMs: this.getCurrentlySelectedVMs(),
                id: this.generateId()
            };

            this.subnets.push(subnet);
            this.createSubnetRegion(subnet);
        }
        this.resetForms();
    }


    async handleFlagFormSubmit(e) {
        e.preventDefault();
        document.querySelectorAll('.error-field').forEach(el => el.classList.remove('error-field'));

        if (!this.validateFlagForm()) return;

        const flagData = {
            flag: this.flagForm['flag-text'].value,
            description: this.flagForm['flag-description'].value,
            points: parseInt(this.flagForm['flag-points'].value),
            order_index: parseInt(this.flagForm['flag-order'].value) || 0
        };

        if (this.selectedFlag) {

            Object.assign(this.selectedFlag, flagData);
            this.flagSubmitButton.textContent = 'Add Flag';
            this.selectedFlag = null;
        } else {

            const flag = {
                ...flagData,
                id: this.generateId()
            };
            this.flags.push(flag);
        }

        this.flagForm.reset();
        this.updateFlagsList();
    }


    async handleHintFormSubmit(e) {
        e.preventDefault();
        document.querySelectorAll('.error-field').forEach(el => el.classList.remove('error-field'));

        if (!this.validateHintForm()) return;

        const hintData = {
            hint_text: this.hintForm['hint-text'].value,
            unlock_points: parseInt(this.hintForm['hint-points'].value) || 0,
            order_index: parseInt(this.hintForm['hint-order'].value) || 0
        };

        if (this.selectedHint) {

            Object.assign(this.selectedHint, hintData);
            this.hintSubmitButton.textContent = 'Add Hint';
            this.selectedHint = null;
        } else {

            const hint = {
                ...hintData,
                id: this.generateId()
            };
            this.hints.push(hint);
        }

        this.hintForm.reset();
        this.updateHintsList();
    }


    async handleCTFSubmit() {
        if (!this.validateCTF()) return;

        this.ctfSubmitButton.disabled = true;
        this.ctfSubmitButton.innerHTML = '<span class="loading-spinner"></span> Creating Challenge...';

        const overlay = this.createLoadingOverlay();
        document.body.appendChild(overlay);

        try {
            const formData = new FormData();
            formData.append('name', this.ctfForm.name.value);
            formData.append('description', this.ctfForm.description.value);
            formData.append('category', this.ctfForm.category.value);
            formData.append('difficulty', this.ctfForm.difficulty.value);
            formData.append('hint', this.ctfForm.hint.value);
            formData.append('solution', this.ctfForm.solution.value);

            const imageInput = document.querySelector('input[type="file"]');
            if (imageInput?.files[0]) {
                formData.append('image', imageInput.files[0]);
            }

            formData.append('vms', JSON.stringify(this.vms.map(vm => {
                const ova = this.availableOVAs.find(o => o.id == vm.ova_id);
                return {
                    name: vm.name,
                    ova_name: vm.ova_name,
                    cores: vm.cores,
                    ram_gb: vm.ram,
                    domain_name: vm.ip
                };
            })));

            formData.append('subnets', JSON.stringify(this.subnets.map(subnet => ({
                name: subnet.name,
                dmz: subnet.dmz,
                accessible: subnet.accessible,
                attached_vms: subnet.attachedVMs.map(vmId => this.vms.find(vm => vm.id === vmId).name)
            }))));

            formData.append('flags', JSON.stringify(this.flags.map(flag => ({
                flag: flag.flag,
                description: flag.description,
                points: flag.points,
                order_index: flag.order_index
            }))));

            formData.append('hints', JSON.stringify(this.hints.map(hint => ({
                hint_text: hint.hint_text,
                unlock_points: hint.unlock_points,
                order_index: hint.order_index
            }))));

            const response = await apiClient.post('../backend/create-ctf.php', formData);

            if (response?.success) {
                messageManager.showSuccess('CTF Challenge created successfully!');
                setTimeout(() => window.location.href = '/dashboard', 1500);
            } else if (response?.errors) {
                const errorFields = response.fields || [];
                const errorMessages = response.errors.join('<br>');

                this.showError(errorMessages, errorFields);
            }
        } catch (error) {
            console.error('CTF submission error:', error);
            messageManager.showError('Failed to create CTF');
        } finally {
            this.ctfSubmitButton.disabled = false;
            this.ctfSubmitButton.innerHTML = 'Create Challenge';
            if (document.body.contains(overlay)) {
                document.body.removeChild(overlay);
            }
        }
    }

    createLoadingOverlay() {
        const overlay = document.createElement('div');
        overlay.style.position = 'fixed';
        overlay.style.top = '0';
        overlay.style.left = '0';
        overlay.style.width = '100%';
        overlay.style.height = '100%';
        overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
        overlay.style.zIndex = '9999';
        overlay.style.display = 'flex';
        overlay.style.justifyContent = 'center';
        overlay.style.alignItems = 'center';
        overlay.innerHTML = '<div style="color: white; font-size: 1.5rem;">Creating your challenge, please wait...</div>';
        return overlay;
    }


    validateCTF() {
        const errors = [];
        const fields = [];


        if (!this.ctfForm.name.value.trim()) {
            errors.push('CTF name is required');
            fields.push('ctf-name');
        } else if (this.ctfForm.name.value.length > this.config.MAX_CTF_NAME_LENGTH) {
            errors.push(`CTF name cannot exceed ${this.config.MAX_CTF_NAME_LENGTH} characters`);
            fields.push('ctf-name');
        } else if (!this.config.CTF_NAME_REGEX.test(this.ctfForm.name.value)) {
            errors.push(`CTF name contains invalid characters`);
            fields.push('ctf-name');
        }


        if (!this.ctfForm.description.value.trim()) {
            errors.push('Description is required');
            fields.push('ctf-description');
        } else if (this.ctfForm.description.value.length > this.config.MAX_CTF_DESCRIPTION_LENGTH) {
            errors.push(`Description cannot exceed ${this.config.MAX_CTF_DESCRIPTION_LENGTH} characters`);
            fields.push('ctf-description');
        }


        if (this.ctfForm.hint.value && this.ctfForm.hint.value.length > this.config.MAX_GENERAL_HINT_LENGTH) {
            errors.push(`General hint cannot exceed ${this.config.MAX_GENERAL_HINT_LENGTH} characters`);
            fields.push('ctf-hint');
        }


        if (this.ctfForm.solution.value && this.ctfForm.solution.value.length > this.config.MAX_SOLUTION_LENGTH) {
            errors.push(`Solution cannot exceed ${this.config.MAX_SOLUTION_LENGTH} characters`);
            fields.push('ctf-solution');
        }


        const imageInput = document.querySelector('input[type="file"]');
        if (imageInput?.files[0]) {
            const file = imageInput.files[0];
            if (file.size > this.config.MAX_CTF_IMAGE_SIZE) {
                errors.push(`Image size cannot exceed ${this.config.MAX_CTF_IMAGE_SIZE / (1024 * 1024)}MB`);
                fields.push('ctf-image-preview');
            }
            if (!this.config.ALLOWED_IMAGE_TYPES.includes(file.type)) {
                errors.push(`Only ${this.config.ALLOWED_IMAGE_TYPES.join(', ')} image types are allowed`);
                fields.push('ctf-image-preview');
            }
        }


        if (this.vms.length === 0) {
            errors.push('Please add at least one VM');
            this.tabVM.click();
        } else if (this.vms.length > this.config.MAX_VM_COUNT) {
            errors.push(`Maximum of ${this.config.MAX_VM_COUNT} VMs allowed`);
        }


        if (this.subnets.length === 0) {
            errors.push('Please add at least one Subnet');
            this.tabSubnet.click();
        } else if (this.subnets.length > this.config.MAX_SUBNET_COUNT) {
            errors.push(`Maximum of ${this.config.MAX_SUBNET_COUNT} subnets allowed`);
        }


        if (this.flags.length === 0) {
            errors.push('Please add at least one flag');
            this.tabFlag.click();
        } else if (this.flags.length > this.config.MAX_FLAG_COUNT) {
            errors.push(`Maximum of ${this.config.MAX_FLAG_COUNT} flags allowed`);
        }


        if (this.hints.length > this.config.MAX_HINT_COUNT) {
            errors.push(`Maximum of ${this.config.MAX_HINT_COUNT} hints allowed`);
        }


        const vmNames = new Set();
        this.vms.forEach(vm => {
            if (vmNames.has(vm.name)) {
                errors.push(`Duplicate VM name: ${vm.name}`);
            }
            vmNames.add(vm.name);
        });

        const subnetNames = new Set();
        this.subnets.forEach(subnet => {
            if (subnetNames.has(subnet.name)) {
                errors.push(`Duplicate subnet name: ${subnet.name}`);
            }
            subnetNames.add(subnet.name);
        });

        try {
            this.validateNetworkReachability();
        } catch (error) {
            errors.push(error.message);
            this.tabSubnet.click();
        }

        if (errors.length) {
            this.showError(errors.join('<br>'), fields);
            return false;
        }
        return true;
    }

    validateVMForm() {
        const errors = [];
        const fields = [];
        const vmName = this.vmForm['vm-name'].value.trim();
        const domain = this.vmForm['vm-ip'].value.trim();

        if (!vmName) {
            errors.push('VM name is required');
            fields.push('vm-name');
        } else if (vmName.length > this.config.MAX_VM_NAME_LENGTH) {
            errors.push(`VM name cannot exceed ${this.config.MAX_VM_NAME_LENGTH} characters`);
            fields.push('vm-name');
        } else if (!this.config.VM_SUBNET_NAME_REGEX.test(vmName)) {
            errors.push(`VM name contains invalid characters`);
            fields.push('ctf-name');
        }

        if (!this.vmForm['vm-ova'].value) {
            errors.push('Please select an OVA template');
            fields.push('vm-ova');
        }

        const cores = parseInt(this.vmForm['vm-cores'].value);
        if (isNaN(cores) || cores < 1 || cores > this.config.MAX_VM_CORES) {
            errors.push(`CPU cores must be between 1-${this.config.MAX_VM_CORES}`);
            fields.push('vm-cores');
        }

        const ram = parseInt(this.vmForm['vm-ram'].value);
        if (isNaN(ram) || ram < 1 || ram > this.config.MAX_VM_RAM) {
            errors.push(`RAM must be between 1-${this.config.MAX_VM_RAM} GB`);
            fields.push('vm-ram');
        }

        if (!domain) {
            errors.push('Domain name is required');
            fields.push('vm-ip');
        } else if (domain.length > this.config.MAX_VM_DOMAIN_LENGTH) {
            errors.push(`Domain cannot exceed ${this.config.MAX_VM_DOMAIN_LENGTH} characters`);
            fields.push('vm-ip');
        } else if (domain.includes(' ')) {
            errors.push('Domain cannot contain spaces');
            fields.push('vm-ip');
        } else if (!this.config.DOMAIN_REGEX.test(domain)) {
            errors.push('Invalid domain format');
            fields.push('vm-ip');
        }

        if (errors.length) {
            this.showError(errors.join('<br>'), fields);
            return false;
        }
        return true;
    }

    validateSubnetForm() {
        const errors = [];
        const fields = [];
        const subnetName = this.subnetForm['subnet-name'].value.trim();
        const attachedVMs = this.getCurrentlySelectedVMs();

        if (!subnetName) {
            errors.push('Subnet name is required');
            fields.push('subnet-name');
        } else if (subnetName.length > this.config.MAX_SUBNET_NAME_LENGTH) {
            errors.push(`Subnet name cannot exceed ${this.config.MAX_SUBNET_NAME_LENGTH} characters`);
            fields.push('subnet-name');
        } else if (!this.config.VM_SUBNET_NAME_REGEX.test(subnetName)) {
            errors.push('Subnet name contains invalid characters');
            fields.push('subnet-name');
        }

        if (attachedVMs.length === 0) {
            errors.push('At least one VM must be attached');
            if (this.vms.length === 0) {
                this.tabVM.click();
            }
        }

        if (errors.length) {
            this.showError(errors.join('<br>'), fields);
            return false;
        }
        return true;
    }

    validateFlagForm() {
        const errors = [];
        const fields = [];
        const flagText = this.flagForm['flag-text'].value.trim();
        const flagDescription = this.flagForm['flag-description'].value.trim();
        const flagPoints = parseInt(this.flagForm['flag-points'].value);

        if (!flagText) {
            errors.push('Flag text is required');
            fields.push('flag-text');
        } else if (flagText.length > this.config.MAX_FLAG_LENGTH) {
            errors.push(`Flag cannot exceed ${this.config.MAX_FLAG_LENGTH} characters`);
            fields.push('flag-text');
        }

        if (flagDescription && flagDescription.length > this.config.MAX_FLAG_DESCRIPTION_LENGTH) {
            errors.push(`Flag description cannot exceed ${this.config.MAX_FLAG_DESCRIPTION_LENGTH} characters`);
            fields.push('flag-description');
        }

        if (isNaN(flagPoints) || flagPoints < 1) {
            errors.push('Points must be at least 1');
            fields.push('flag-points');
        } else if (flagPoints > this.config.MAX_FLAG_POINTS) {
            errors.push(`Maximum points per flag is ${this.config.MAX_FLAG_POINTS}`);
            fields.push('flag-points');
        }

        if (errors.length) {
            this.showError(errors.join('<br>'), fields);
            return false;
        }
        return true;
    }

    validateHintForm() {
        const errors = [];
        const fields = [];
        const hintText = this.hintForm['hint-text'].value.trim();
        const hintPoints = parseInt(this.hintForm['hint-points'].value);

        if (!hintText) {
            errors.push('Hint text is required');
            fields.push('hint-text');
        } else if (hintText.length > this.config.MAX_HINT_LENGTH) {
            errors.push(`Hint cannot exceed ${this.config.MAX_HINT_LENGTH} characters`);
            fields.push('hint-text');
        }

        if (isNaN(hintPoints) || hintPoints < 0) {
            errors.push('Points must be 0 or greater');
            fields.push('hint-points');
        } else if (hintPoints > this.config.MAX_HINT_POINTS) {
            errors.push(`Maximum points per hint is ${this.config.MAX_HINT_POINTS}`);
            fields.push('hint-points');
        }

        if (errors.length) {
            this.showError(errors.join('<br>'), fields);
            return false;
        }
        return true;
    }

    validateNetworkReachability() {
        const vms = this.vms;
        const subnets = this.subnets.map(subnet => ({
            name: subnet.name,
            accessible: subnet.accessible,
            attached_vms: subnet.attachedVMs.map(vmId => {
                const vm = this.vms.find(v => v.id === vmId);
                return vm ? vm.name : '';
            }).filter(name => name)
        }));

        for (const subnet of subnets) {
            if (subnet.attached_vms.length === 0) {
                throw new Error(
                    `Subnet '${subnet.name}' has no attached VMs. Remove it or add VMs.`
                );
            }
        }

        const vmSubnetMap = {};
        const subnetVmMap = {};
        const publicSubnets = [];

        for (const subnet of subnets) {
            const subnetName = subnet.name;
            subnetVmMap[subnetName] = subnet.attached_vms;

            if (subnet.accessible) {
                publicSubnets.push(subnetName);
            }

            for (const vmName of subnet.attached_vms) {
                if (!vmSubnetMap[vmName]) {
                    vmSubnetMap[vmName] = [];
                }
                vmSubnetMap[vmName].push(subnetName);
            }
        }

        const isVMReachable = (vmName, vmSubnetMap, subnetVmMap, publicSubnets) => {
            const visitedSubnets = new Set();
            const queue = [...(vmSubnetMap[vmName] || [])];

            while (queue.length > 0) {
                const currentSubnet = queue.shift();

                if (publicSubnets.includes(currentSubnet)) {
                    return true;
                }

                if (visitedSubnets.has(currentSubnet)) {
                    continue;
                }

                visitedSubnets.add(currentSubnet);

                for (const neighborVm of subnetVmMap[currentSubnet] || []) {
                    for (const neighborSubnet of vmSubnetMap[neighborVm] || []) {
                        if (!visitedSubnets.has(neighborSubnet)) {
                            queue.push(neighborSubnet);
                        }
                    }
                }
            }

            return false;
        };

        const unreachableVms = [];
        for (const vm of vms) {
            const vmName = vm.name;
            if (!isVMReachable(vmName, vmSubnetMap, subnetVmMap, publicSubnets)) {
                unreachableVms.push(vmName);
            }
        }

        if (unreachableVms.length > 0) {
            throw new Error(
                `Unreachable VMs detected (no path to public subnets): ${unreachableVms.join(', ')}`
            );
        }

        for (const subnet of subnets) {
            const subnetName = subnet.name;
            let onlyHere = true;

            for (const vm of subnet.attached_vms) {
                if ((vmSubnetMap[vm] || []).length > 1) {
                    onlyHere = false;
                    break;
                }
            }

            if (onlyHere && !subnet.accessible) {
                throw new Error(
                    `Subnet '${subnetName}' is not reachable and contains only VMs that are exclusively in it. These VMs would be isolated.`
                );
            }
        }
    }

    updateFlagsList() {
        this.flagsList.innerHTML = '';
        const sortedFlags = [...this.flags].sort((a, b) => a.order_index - b.order_index);

        sortedFlags.forEach(flag => {
            const flagItem = document.createElement('div');
            flagItem.className = 'list-item';
            if (this.selectedFlag?.id === flag.id) flagItem.classList.add('selected');

            flagItem.innerHTML = `
                <div class="flag-icon"><i class="fa-solid fa-flag"></i></div>
                <div class="flag-content">
                    <div class="flag-title">${flag.flag}</div>
                    <div class="flag-meta">
                        ${flag.points} points • ${flag.description || 'No description'}
                    </div>
                </div>
                <div class="flag-actions">
                    <button class="edit-flag" title="Edit"><i class="fa-solid fa-edit"></i></button>
                    <button class="delete-flag" title="Delete"><i class="fa-solid fa-trash"></i></button>
                </div>
            `;

            flagItem.querySelector('.edit-flag').addEventListener('click', (e) => {
                e.stopPropagation();
                this.selectFlag(flag);
            });

            flagItem.querySelector('.delete-flag').addEventListener('click', async (e) => {
                e.stopPropagation();
                const confirmed = await this.confirmAction('Delete this Flag?');
                if (confirmed) {
                    const index = this.flags.findIndex(f => f.id === flag.id);
                    if (index !== -1) {
                        this.flags.splice(index, 1);
                        this.updateFlagsList();
                    }
                }
            });

            this.flagsList.appendChild(flagItem);
        });
    }

    updateHintsList() {
        this.hintsList.innerHTML = '';
        const sortedHints = [...this.hints].sort((a, b) => a.order_index - b.order_index);

        sortedHints.forEach(hint => {
            const hintItem = document.createElement('div');
            hintItem.className = 'list-item';
            if (this.selectedHint?.id === hint.id) hintItem.classList.add('selected');

            hintItem.innerHTML = `
                <div class="hint-icon"><i class="fa-solid fa-lightbulb"></i></div>
                <div class="hint-content">
                    <div class="hint-text">${hint.hint_text}</div>
                    <div class="hint-meta">Unlocks at ${hint.unlock_points} points</div>
                </div>
                <div class="hint-actions">
                    <button class="edit-hint" title="Edit"><i class="fa-solid fa-edit"></i></button>
                    <button class="delete-hint" title="Delete"><i class="fa-solid fa-trash"></i></button>
                </div>
            `;

            hintItem.querySelector('.edit-hint').addEventListener('click', (e) => {
                e.stopPropagation();
                this.selectHint(hint);
            });

            hintItem.querySelector('.delete-hint').addEventListener('click', async (e) => {
                e.stopPropagation();
                const confirmed = await this.confirmAction('Delete this Hint?');
                if (confirmed) {
                    const index = this.hints.findIndex(h => h.id === hint.id);
                    if (index !== -1) {
                        this.hints.splice(index, 1);
                        this.updateHintsList();
                    }
                }
            });

            this.hintsList.appendChild(hintItem);
        });
    }

    async confirmAction(message) {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = 'confirmation-modal';
            modal.innerHTML = `
                <div class="modal-content">
                    <p>${message}</p>
                    <div class="modal-buttons">
                        <button class="cancel-btn">Cancel</button>
                        <button class="confirm-btn">Confirm</button>
                    </div>
                </div>
            `;

            document.body.appendChild(modal);

            modal.querySelector('.cancel-btn').addEventListener('click', () => {
                document.body.removeChild(modal);
                resolve(false);
            });

            modal.querySelector('.confirm-btn').addEventListener('click', () => {
                document.body.removeChild(modal);
                resolve(true);
            });
        });
    }


    selectFlag(flag) {
        this.clearSelection();
        this.selectedFlag = flag;

        document.querySelectorAll('#flags-list .list-item').forEach(item => {
            item.classList.remove('selected');
            if (item.querySelector('.flag-title')?.textContent === flag.flag) {
                item.classList.add('selected');
            }
        });

        this.flagForm['flag-text'].value = flag.flag;
        this.flagForm['flag-description'].value = flag.description || '';
        this.flagForm['flag-points'].value = flag.points;
        this.flagForm['flag-order'].value = flag.order_index;
        this.flagSubmitButton.textContent = 'Update Flag';

        if (!this.flagInput.classList.contains('active')) {
            this.switchTab(this.tabFlag, this.flagInput);
        }
    }

    selectHint(hint) {
        this.clearSelection();
        this.selectedHint = hint;

        document.querySelectorAll('#hints-list .list-item').forEach(item => {
            item.classList.remove('selected');
            if (item.querySelector('.hint-text')?.textContent === hint.hint_text) {
                item.classList.add('selected');
            }
        });

        this.hintForm['hint-text'].value = hint.hint_text;
        this.hintForm['hint-points'].value = hint.unlock_points;
        this.hintForm['hint-order'].value = hint.order_index;
        this.hintSubmitButton.textContent = 'Update Hint';

        if (!this.hintInput.classList.contains('active')) {
            this.switchTab(this.tabHint, this.hintInput);
        }
    }

    getCurrentlySelectedVMs() {
        const selectedVMs = [];
        document.querySelectorAll('#vm-checkbox-list .vm-checkbox-item.selected').forEach(item => {
            selectedVMs.push(item.getAttribute('data-vm-id'));
        });
        return selectedVMs;
    }


    createVMIcon(vm) {
        const icon = document.createElement('div');
        icon.className = 'vm-icon';
        icon.setAttribute('data-id', vm.id);
        icon.draggable = true;

        icon.innerHTML = `
            <button class="remove-vm-btn" title="Remove">&times;</button>
            <i class="fa-solid fa-desktop"></i>
            <span>${vm.name}</span>
            <small>${vm.ip}</small>
        `;

        icon.querySelector('.remove-vm-btn').addEventListener('click', async (e) => {
            e.stopPropagation();
            const confirmed = await this.confirmAction('Delete this VM?');
            if (confirmed) this.removeVM(vm.id);
        });

        icon.addEventListener('click', (e) => {
            if (e.target !== icon.querySelector('.remove-vm-btn')) {
                this.selectVM(vm);
            }
        });

        icon.addEventListener('dragstart', (e) => {
            e.dataTransfer.setData('text/plain', vm.id);
        });

        this.vmIconsContainer.appendChild(icon);
        this.updateLayout();
    }

    updateVMIcon(vm) {
        const icon = this.vmIconsContainer.querySelector(`.vm-icon[data-id="${vm.id}"]`);
        if (icon) {
            icon.innerHTML = `
                <button class="remove-vm-btn" title="Remove">&times;</button>
                <i class="fa-solid fa-desktop"></i>
                <span>${vm.name}</span>
                <small>${vm.ip}</small>
            `;

            icon.querySelector('.remove-vm-btn').addEventListener('click', async (e) => {
                e.stopPropagation();
                const confirmed = await this.confirmAction('Delete this VM?');
                if (confirmed) this.removeVM(vm.id);
            });

            icon.addEventListener('click', (e) => {
                if (e.target !== icon.querySelector('.remove-vm-btn')) {
                    this.selectVM(vm);
                }
            });
        }
    }


    createSubnetRegion(subnet) {
        const region = document.createElement('div');
        region.className = 'subnet-region';
        region.setAttribute('data-id', subnet.id);
        region.style.opacity = '0';
        region.style.transition = 'opacity 0.5s ease';

        const header = document.createElement('div');
        header.className = 'subnet-header';
        header.innerHTML = `
            <h3>${subnet.name}</h3>
            <div class="subnet-btns">
                <button title="Delete Subnet"><i class="fa-solid fa-times"></i></button>
            </div>
        `;

        const vmContainer = document.createElement('div');
        vmContainer.className = 'subnet-vm-container';
        region.appendChild(header);
        region.appendChild(vmContainer);

        region.addEventListener('dragover', (e) => e.preventDefault());
        region.addEventListener('drop', (e) => {
            e.preventDefault();
            const vmId = e.dataTransfer.getData('text/plain');
            if (!subnet.attachedVMs.includes(vmId)) {
                subnet.attachedVMs.push(vmId);
                this.updateSubnetVMs(region, subnet.attachedVMs);
                this.updateLayout()
            }
        });

        region.addEventListener('click', (e) => {
            if (!e.target.closest('.subnet-btns') && !e.target.closest('.vm-icon')) {
                this.selectSubnet(subnet);
            }
        });

        this.updateSubnetVMs(region, subnet.attachedVMs);

        header.querySelector('button').addEventListener('click', async (e) => {
            e.stopPropagation();
            const confirmed = await this.confirmAction('Delete this Subnet?');
            if (confirmed) {
                this.subnetRegionsContainer.removeChild(region);
                const index = this.subnets.findIndex(s => s.id === subnet.id);
                if (index !== -1) this.subnets.splice(index, 1);
                this.updateLayout();
                this.positionSubnetRegions();
                if (this.selectedSubnet?.id === subnet.id) this.clearSelection();
            }
        });

        this.subnetRegionsContainer.appendChild(region);
        requestAnimationFrame(() => region.style.opacity = '1');
        this.updateLayout();
        this.positionSubnetRegions();
    }

    updateSubnetRegion(subnet) {
        const region = this.subnetRegionsContainer.querySelector(`.subnet-region[data-id="${subnet.id}"]`);
        if (region) {
            const header = region.querySelector('.subnet-header');
            if (header) header.querySelector('h3').textContent = subnet.name;
            this.updateSubnetVMs(region, subnet.attachedVMs);
        }
        this.updateLayout();
    }

    updateSubnetVMs(region, attachedVMs) {
        const vmContainer = region.querySelector('.subnet-vm-container');
        vmContainer.innerHTML = '';

        const totalSubnets = this.subnets.length;
        const vmCount = attachedVMs.length;

        vmContainer.classList.remove('small-mode', 'smallest-mode');
        if (totalSubnets === 2 && vmCount >= 5) vmContainer.classList.add('small-mode');
        if (totalSubnets >= 3 && vmCount >= 3) vmContainer.classList.add('smallest-mode');

        const subnetHeader = region.querySelector('.subnet-header');
        if (subnetHeader) {
            subnetHeader.style.marginBottom = (totalSubnets >= 3 && vmCount > 2) ? '0px' : '';
        }

        attachedVMs.forEach(vmId => {
            const vm = this.vms.find(v => v.id === vmId);
            if (vm) {
                const icon = document.createElement('div');
                icon.className = 'vm-icon' +
                    (totalSubnets === 2 && vmCount >= 5 ? ' vm-icon-small' : '') +
                    (totalSubnets >= 3 && vmCount >= 3 ? ' vm-icon-smallest' : '');
                icon.setAttribute('data-id', vm.id);

                icon.innerHTML = `
                    <button class="remove-vm-btn" title="Remove">&times;</button>
                    <i class="fa-solid fa-desktop"></i>
                    <span>${vm.name}</span>
                    <small>${vm.ip}</small>
                `;

                icon.querySelector('.remove-vm-btn').addEventListener('click', (e) => {
                    e.stopPropagation();
                    const idx = attachedVMs.indexOf(vm.id);
                    if (idx !== -1) {
                        attachedVMs.splice(idx, 1);
                        this.updateSubnetVMs(region, attachedVMs);
                        this.updateLayout();
                    }
                });

                icon.addEventListener('click', (e) => {
                    if (e.target !== icon.querySelector('.remove-vm-btn')) {
                        this.selectVM(vm);
                    }
                });

                vmContainer.appendChild(icon);
            }
        });
    }

    selectVM(vm) {
        this.clearSelection();

        const icon = this.vmIconsContainer.querySelector(`.vm-icon[data-id="${vm.id}"]`);
        if (icon) icon.classList.add('selected');

        document.querySelectorAll('.subnet-region .vm-icon').forEach(subnetIcon => {
            if (subnetIcon.getAttribute('data-id') === vm.id) {
                subnetIcon.classList.add('selected');
            }
        });

        if (!this.vmInput.classList.contains('active')) {
            this.switchTab(this.tabVM, this.vmInput);
        }

        this.vmForm['vm-name'].value = vm.name;
        this.vmForm['vm-ova'].value = vm.ova_id;
        this.vmForm['vm-cores'].value = vm.cores;
        this.vmForm['vm-ram'].value = vm.ram;
        this.vmForm['vm-ip'].value = vm.ip;
        this.vmSubmitButton.textContent = 'Update VM';

        this.selectedVM = vm;
    }

    selectSubnet(subnet) {
        if (!this.subnetInput.classList.contains('active')) {
            this.switchTab(this.tabSubnet, this.subnetInput);
        }

        this.clearSelection();
        this.selectedSubnet = subnet;

        const region = this.subnetRegionsContainer.querySelector(`.subnet-region[data-id="${subnet.id}"]`);
        if (region) region.classList.add('selected');

        this.subnetForm['subnet-name'].value = subnet.name;
        this.subnetForm['subnet-dmz'].checked = subnet.dmz;
        this.subnetForm['subnet-accessible'].checked = subnet.accessible;
        this.updateSubnetVMsDropdown();
        this.subnetSubmitButton.textContent = 'Update Subnet';
    }

    clearSelection() {
        if (this.selectedVM) {
            document.querySelectorAll(`.vm-icon[data-id="${this.selectedVM.id}"]`).forEach(icon => {
                icon.classList.remove('selected');
            });
            this.selectedVM = null;
        }

        if (this.selectedSubnet) {
            document.querySelectorAll(`.subnet-region[data-id="${this.selectedSubnet.id}"]`).forEach(region => {
                region.classList.remove('selected');
            });
            this.selectedSubnet = null;
        }

        this.resetForms();
        this.vmSubmitButton.textContent = 'Add VM';
        this.subnetSubmitButton.textContent = 'Add Subnet';
    }

    removeVM(vmId) {
        const icon = this.vmIconsContainer.querySelector(`.vm-icon[data-id="${vmId}"]`);
        if (icon) this.vmIconsContainer.removeChild(icon);

        this.subnets.forEach(subnet => {
            subnet.attachedVMs = subnet.attachedVMs.filter(id => id !== vmId);
        });

        const index = this.vms.findIndex(vm => vm.id === vmId);
        if (index !== -1) this.vms.splice(index, 1);

        document.querySelectorAll('.subnet-region').forEach(region => {
            const subnetId = region.getAttribute('data-id');
            const subnet = this.subnets.find(s => s.id === subnetId);
            if (subnet) this.updateSubnetVMs(region, subnet.attachedVMs);
        });

        this.updateSubnetVMsDropdown();

        if (this.selectedVM?.id === vmId) this.clearSelection();
        this.updateLayout();
    }

    updateSubnetVMsDropdown() {
        const vmList = document.getElementById('vm-checkbox-list');
        vmList.innerHTML = '';

        const attachedVMs = this.selectedSubnet ? this.selectedSubnet.attachedVMs : [];

        this.vms.forEach(vm => {
            const item = document.createElement('div');
            item.className = 'vm-checkbox-item';
            item.setAttribute('data-vm-id', vm.id);

            const isSelected = attachedVMs.includes(vm.id);
            if (isSelected) item.classList.add('selected');

            item.innerHTML = `
                <div class="vm-checkbox-icon">
                    <i class="fa-solid ${isSelected ? 'fa-check' : 'fa-times'}"></i>
                </div>
                <div class="vm-checkbox-label">
                    ${vm.name} <span class="vm-checkbox-ip">(${vm.ip})</span>
                </div>
            `;

            item.addEventListener('click', () => {
                this.toggleVMSelection(vm.id, item);
            });

            vmList.appendChild(item);
        });
    }

    toggleVMSelection(vmId, item) {
        if (!this.selectedSubnet) {
            this.selectedSubnet = {
                id: 'temp',
                name: this.subnetForm['subnet-name'].value || 'New Subnet',
                dmz: this.subnetForm['subnet-dmz'].checked || false,
                accessible: this.subnetForm['subnet-accessible'].checked || false,
                attachedVMs: this.getCurrentlySelectedVMs()
            };
        }

        const index = this.selectedSubnet.attachedVMs.indexOf(vmId);
        if (index === -1) {
            this.selectedSubnet.attachedVMs.push(vmId);
            item.classList.add('selected');
            item.querySelector('.vm-checkbox-icon i').className = 'fa-solid fa-check';
        } else {
            this.selectedSubnet.attachedVMs.splice(index, 1);
            item.classList.remove('selected');
            item.querySelector('.vm-checkbox-icon i').className = 'fa-solid fa-times';
        }

        if (this.selectedSubnet.id === 'temp') {
            this.selectedSubnet = null;
        }
    }

    generateId() {
        return '_' + Math.random().toString(36).substr(2, 9);
    }

    positionSubnetRegions() {
        const regions = this.subnetRegionsContainer.querySelectorAll('.subnet-region');
        const count = regions.length;
        const containerWidth = this.subnetRegionsContainer.clientWidth;
        const containerHeight = this.subnetRegionsContainer.clientHeight;
        const isExpanded = document.querySelector('.create-ctf-container').classList.contains('expanded-layout');

        let columns, rows;

        if (isExpanded) {
            if (count === 1) {
                columns = 1;
                rows = 1;
            } else if (count === 2) {
                columns = 2;
                rows = 1;
            } else if (count <= 4) {
                columns = 2;
                rows = 2;
            } else if (count <= 6) {
                columns = 3;
                rows = 2;
            } else if (count <= 9) {
                columns = 3;
                rows = 3;
            } else if (count <= 12) {
                columns = 4;
                rows = 3;
            } else {
                columns = 4;
                rows = 4;
            }
        } else {
            if (count <= 2) {
                columns = count;
                rows = 1;
            } else {
                columns = 2;
                rows = Math.ceil(count / 2);
            }
        }

        const cellWidth = containerWidth / columns;
        const cellHeight = containerHeight / rows;

        regions.forEach((region, index) => {
            const col = index % columns;
            const row = Math.floor(index / columns);

            region.style.position = 'absolute';
            region.style.width = `${cellWidth * 0.9}px`;
            region.style.height = `${cellHeight * 0.9}px`;
            region.style.left = `${col * cellWidth + cellWidth * 0.05}px`;
            region.style.top = `${row * cellHeight + cellHeight * 0.05}px`;
        });

        regions.forEach(region => {
            const subnetId = region.getAttribute('data-id');
            const subnet = this.subnets.find(s => s.id === subnetId);
            if (subnet) this.updateSubnetVMs(region, subnet.attachedVMs);
        });
    }

    resetForms() {
        this.vmForm.reset();
        this.subnetForm.reset();
        this.flagForm.reset();
        this.hintForm.reset();
        this.vmSubmitButton.textContent = 'Add VM';
        this.subnetSubmitButton.textContent = 'Add Subnet';
        this.updateSubnetVMsDropdown();
    }

    updateLayout() {
        const container = document.querySelector('.create-ctf-container');
        const subnetCount = this.subnets.length;
        const vmCount = this.vms.length;

        const needsExpandedLayout =
            vmCount > 11 ||
            subnetCount > 4 ||
            (subnetCount === 2 && this.subnets.some(s => s.attachedVMs.length > 6)) ||
            (subnetCount >= 3 && subnetCount <= 4 && this.subnets.some(s => s.attachedVMs.length > 4));

        container.classList.add('layout-transitioning');
        container.classList.remove('expanded-layout', 'compact-layout');

        if (needsExpandedLayout) {
            container.classList.add('expanded-layout');
            document.querySelector('.visual-canvas').style.height = '900px';
        } else {
            container.classList.add('compact-layout');
            document.querySelector('.visual-canvas').style.height = '400px';
        }

        setTimeout(() => {
            container.classList.remove('layout-transitioning');
            this.positionSubnetRegions();
        }, 400);
    }

    async fetchAvailableOVAs() {
        try {
            const response = await apiClient.get('../backend/create-ctf.php?');

            if (response?.success) {
                this.availableOVAs = response.ovas;
                this.updateOVADropdown();
            }
        } catch (error) {
            console.error('OVA fetch error:', error);
            messageManager.showError('Failed to load OVA templates');
        }
    }

    updateOVADropdown() {
        this.ovaDropdown.innerHTML = '<option value="">-- Select OVA --</option>';

        this.availableOVAs.forEach(ova => {
            const option = document.createElement('option');
            option.value = ova.id;

            const uploadDate = new Date(ova.date);
            const formattedDate = uploadDate.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });

            option.textContent = `${ova.name} (${formattedDate})`;
            this.ovaDropdown.appendChild(option);
        });

        const ovaId = new URLSearchParams(window.location.search).get('ova');
        const selectedOva = this.availableOVAs.find(ova => ova.id == ovaId);
        if (ovaId && selectedOva) {
            this.switchTab(this.tabVM, this.vmInput);
            this.ovaDropdown.value = selectedOva.id;
            const selectedOption = this.ovaDropdown.querySelector(`option[value="${selectedOva.id}"]`);
            if (selectedOption) {
                selectedOption.style.backgroundColor = 'rgba(0, 173, 181, 0.2)';
            }
        }
    }

    setupImageUpload() {
        const imageContainer = document.querySelector('.general-info-image-container');
        const imagePreview = this.ctfForm.image;
        const imageInput = document.createElement('input');
        imageInput.type = 'file';
        imageInput.accept = this.config.ALLOWED_IMAGE_TYPES.join(',');
        imageInput.style.display = 'none';
        document.body.appendChild(imageInput);

        imageContainer.addEventListener('click', () => imageInput.click());

        imageInput.onchange = (e) => {
            const file = e.target.files[0];
            if (file) {

                if (file.size > this.config.MAX_CTF_IMAGE_SIZE) {
                    this.showError(`Image size cannot exceed ${this.config.MAX_CTF_IMAGE_SIZE / (1024 * 1024)}MB`, ['ctf-image-preview']);
                    return;
                }
                if (!this.config.ALLOWED_IMAGE_TYPES.includes(file.type)) {
                    this.showError(`Only ${this.config.ALLOWED_IMAGE_TYPES.join(', ')} image types are allowed`, ['ctf-image-preview']);
                    return;
                }

                const reader = new FileReader();
                reader.onload = (event) => {
                    imagePreview.src = event.target.result;
                    imagePreview.style.opacity = '0';
                    imagePreview.style.transform = 'scale(0.8)';
                    setTimeout(() => {
                        imagePreview.style.opacity = '1';
                        imagePreview.style.transform = 'scale(1)';
                    }, 50);
                };
                reader.readAsDataURL(file);
            }
        };
    }
}


document.addEventListener('DOMContentLoaded', () => {
    new CTFCreator();
});