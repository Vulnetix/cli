<script setup>
import { computed } from 'vue';
import { getPastelColor } from '@/utils';

const props = defineProps({
    dependencies: {
        type: Array,
        required: true,
    },
})

const roots = computed(() => {
    const childKeys = new Set(props.dependencies.map(d => d.childOfKey).filter(Boolean));
    return props.dependencies.filter(d => !childKeys.has(d.key));
});

const getChildren = (parentKey) => {
    return props.dependencies.filter(dep => dep.childOfKey === parentKey);
};

const colours = {
    pypi: getPastelColor(),
    golang: getPastelColor(),
    githubactions: getPastelColor(),
}
const getEcosystemColor = (ecosystem) => (colours[ecosystem.toLowerCase()] || getPastelColor());
</script>

<template>
    <v-container
        fluid
        class="pa-0"
        v-if="props.dependencies"
    >
        <v-card>
            <v-card-title>Dependency Tree</v-card-title>
            <v-card-text>
                <div class="tree">
                    <ul>
                        <li
                            v-for="root in roots"
                            :key="root.key"
                        >
                            <div class="d-flex align-center pa-2">
                                <v-chip
                                    :color="getEcosystemColor(root.packageEcosystem)"
                                    size="small"
                                    class="mr-2"
                                >
                                    {{ root.packageEcosystem }}
                                </v-chip>
                                <span class="font-weight-medium">{{ root.name }}</span>
                                <v-chip
                                    outlined
                                    size="small"
                                    class="ml-2"
                                >
                                    {{ root.version }}
                                </v-chip>
                                <v-chip
                                    v-if="root.license"
                                    color="green"
                                    size="small"
                                    class="ml-2"
                                >
                                    {{ root.license }}
                                </v-chip>
                            </div>

                            <ul>
                                <li
                                    v-for="child in getChildren(root.key)"
                                    :key="child.key"
                                >
                                    <div class="d-flex align-center pa-2">
                                        <v-chip
                                            :color="getEcosystemColor(child.packageEcosystem)"
                                            size="small"
                                            class="mr-2"
                                        >
                                            {{ child.packageEcosystem }}
                                        </v-chip>
                                        <span class="font-weight-medium">{{ child.name }}</span>
                                        <v-chip
                                            outlined
                                            size="small"
                                            class="ml-2"
                                        >
                                            {{ child.version }}
                                        </v-chip>
                                        <v-chip
                                            v-if="child.license"
                                            color="green"
                                            size="small"
                                            class="ml-2"
                                        >
                                            {{ child.license }}
                                        </v-chip>
                                    </div>
                                </li>
                            </ul>
                        </li>
                    </ul>
                </div>
            </v-card-text>
        </v-card>
    </v-container>
</template>

<style scoped>
.tree {
    max-height: 800px;
    overflow-y: auto;
    padding: 16px;
}

.tree ul {
    list-style: none;
    padding-left: 20px;
    position: relative;
}

.tree li {
    position: relative;
    padding: 4px 0;
}

.tree li::before {
    content: "";
    position: absolute;
    left: -15px;
    top: 50%;
    width: 15px;
    height: 1px;
    background: #ccc;
}

.tree ul::before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 1px;
    background: #ccc;
}

.tree>ul::before {
    display: none;
}
</style>
