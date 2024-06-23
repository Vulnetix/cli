<script setup>
import { default as axios } from 'axios'
import { reactive } from 'vue'
import { useTheme } from 'vuetify'
import router from "../router"
import { isJSON, isSARIF } from '../utils'

const { global } = useTheme()

const initialState = {
  error: "",
  warning: "",
  success: "",
  info: "",
  loading: false,
  files: [],
  uploads: [],
  github: [],
}

const state = reactive({
  ...initialState,
})

axios.defaults.headers.common = {
  'x-trivialsec': localStorage.getItem('/session/token') || '',
}
class Sarif {
  constructor() {
    this.refresh(true)
  }

  async refresh(initial = false) {
    clearAlerts()
    state.loading = true
    try {
      const { data } = await axios.get(`/sarif/results`)
      state.loading = false

      if (typeof data === "string" && !isJSON(data)) {
        state.warning = "SARIF data could not be retrieved, please try again later."

        return
      }
      if (data?.err) {
        state.error = data.err
      }
      if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
        state.info = data.result

        return setTimeout(router.push('/logout'), 2000)
      }
      if (!data.sarif) {
        state.info = "No SARIF data available."
      } else {
        state.uploads = data.sarif.filter(item => item.source === "upload")
        state.github = data.sarif.filter(item => item.source === "GitHub")
        if (initial !== true) {
          state.info = "Refreshed SARIF"
        }
      }

      return
    } catch (e) {
      console.error(e)
      state.error = `${e.code} ${e.message}`
      state.loading = false
    }
    state.warning = "No SARIF data available."
  }

  async upload() {
    clearAlerts()
    state.loading = true
    const files = []
    try {
      for (const blob of state.files) {
        const text = await blob.text()
        if (!isJSON(text)) {
          state.error = "Provided file does not contain a JSON string."
          break
        }
        const json = JSON.parse(text)
        if (isSARIF(json)) {
          files.push(json)
        } else {
          state.error = "Provided file does not contain valid SARIF."
          break
        }
      }
      if (!files.length) {
        state.warning = "No SARIF files were provided."
        return
      }
      const { data } = await axios.post(`/sarif/upload`, files, { headers: { 'Content-Type': 'application/json' } })
      state.loading = false

      if (typeof data === "string" && !isJSON(data)) {
        state.error = "SARIF data could not be uploaded, please try again later."

        return
      }
      if (data?.err) {
        state.error = data.err
      }
      if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
        state.info = data.result

        return setTimeout(router.push('/logout'), 2000)
      }
      if (!data.sarif) {
        state.info = "No SARIF data available."
      } else {
        state.uploads = data.sarif.filter(item => item.source === "upload")
        state.github = data.sarif.filter(item => item.source === "GitHub")
        state.success = "Refreshed SARIF"
      }

      return
    } catch (e) {
      console.error(e)
      state.error = typeof e === "string" ? e : `${e.code} ${e.message}`
      state.loading = false
    }
  }
}

function clearAlerts() {
  state.error = ''
  state.warning = ''
  state.success = ''
  state.info = ''
}

function groupedByOrg() {
  return state.github.reduce((acc, sarif) => {
    const [orgName, repoName] = sarif.fullName.split('/')
    let group = acc.find(group => group.orgName === orgName)

    if (!group) {
      group = {
        orgName: orgName,
        avatarUrl: sarif?.repo?.avatarUrl,
        sarif: []
      };
      acc.push(group)
    }
    group.sarif.push({ ...sarif, orgName, repoName })
    return acc
  }, [])
}

const sarif = reactive(new Sarif())
</script>

<template>
  <VRow>
    <VCol cols="12">
      <VAlert
        v-if="state.error"
        color="error"
        icon="$error"
        title="Error"
        :text="state.error"
        border="start"
        variant="tonal"
      />
      <VAlert
        v-if="state.warning"
        color="warning"
        icon="$warning"
        title="Warning"
        :text="state.warning"
        border="start"
        variant="tonal"
      />
      <VAlert
        v-if="state.success"
        color="success"
        icon="$success"
        title="Success"
        :text="state.success"
        border="start"
        variant="tonal"
      />
      <VAlert
        v-if="state.info"
        color="info"
        icon="$info"
        title="Information"
        :text="state.info"
        border="start"
        variant="tonal"
      />
    </VCol>

    <VCol cols="12">
      <VBtn
        text="Refresh"
        prepend-icon="mdi-refresh"
        variant="text"
        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
        :disabled="state.loading"
        @click="sarif.refresh"
      />
      <VDialog
        width="50%"
        persistent
      >
        <template v-slot:activator="{ props: activatorProps }">
          <VBtn
            class="text-right"
            prepend-icon="mdi-upload"
            text="Upload SARIF"
            variant="text"
            :color="global.name.value === 'dark' ? '#fff' : '#272727'"
            v-bind="activatorProps"
          />
        </template>
        <template v-slot:default="{ isActive }">
          <VCard title="Select SARIF files">
            <VDivider class="mt-3"></VDivider>
            <VCardText class="px-4">
              <VFileInput
                v-model="state.files"
                :show-size="1000"
                accept="application/json"
                label="File input"
                placeholder="Select your files"
                prepend-icon="mdi-paperclip"
                variant="outlined"
                counter
                multiple
              >
                <template v-slot:selection="{ fileNames }">
                  <template
                    v-for="(fileName, index) in fileNames"
                    :key="fileName"
                  >
                    <VChip
                      v-if="index < 2"
                      class="me-2"
                      size="small"
                      label
                    >
                      {{ fileName }}
                    </VChip>

                    <span
                      v-else-if="index === 2"
                      class="text-overline text-grey-darken-3 mx-2"
                    >
                      +{{ state.files.length - 2 }} File(s)
                    </span>
                  </template>
                </template>
              </VFileInput>
            </VCardText>

            <VDivider></VDivider>
            <VCard-actions class="mt-3">
              <VBtn
                text="Close"
                @click="isActive.value = false"
              />
              <VSpacer></VSpacer>
              <VBtn
                text="Save"
                variant="flat"
                @click="sarif.upload"
              />
            </VCard-actions>
          </VCard>
        </template>
      </VDialog>
    </VCol>

    <VCol
      cols="12"
      v-if="state.github.length || state.loading"
    >
      <VCard title="Github">
        <v-expansion-panels accordion>
          <v-expansion-panel
            v-for="(group, k) in groupedByOrg()"
            :key="k"
          >
            <v-expansion-panel-title class="text-subtitle-1">
              <img
                :src="group.avatarUrl"
                width="25"
                class="me-3"
              >{{ group.orgName }} ({{ group.sarif.length }} results)
            </v-expansion-panel-title>
            <v-expansion-panel-text>
              <VSkeletonLoader
                v-if="state.loading"
                type="table"
              />
              <VTable
                v-else
                height="20rem"
                fixed-header
              >
                <thead>
                  <tr>
                    <th class="text-uppercase">
                      Repository
                    </th>
                    <th>
                      Ref
                    </th>
                    <th>
                      Findings
                    </th>
                    <th>
                      Rules Count
                    </th>
                    <th>
                      Tool
                    </th>
                    <th>
                      Commit SHA
                    </th>
                    <th>
                      Reports
                    </th>
                    <th>
                      Created Date
                    </th>
                  </tr>
                </thead>

                <tbody>
                  <tr
                    v-for="(result, i) in group.sarif"
                    :key="i"
                  >
                    <td>
                      {{ result.repoName }}
                    </td>
                    <td class="text-center">
                      {{ result.ref }}
                    </td>
                    <td class="text-center">
                      {{ result.resultsCount }}
                    </td>
                    <td class="text-center">
                      {{ result.rulesCount }}
                    </td>
                    <td class="text-center">
                      {{ result.toolName }} {{ result.toolVersion }}
                    </td>
                    <td class="text-center">
                      {{ result.commitSha }}
                    </td>
                    <td class="text-center">
                      {{ result.results.length }}
                    </td>
                    <td class="text-center">
                      {{ new Date(result.createdAt).toLocaleDateString() }}
                    </td>
                  </tr>
                </tbody>
              </VTable>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </VCard>
    </VCol>
    <VCol
      cols="12"
      v-if="state.uploads.length || state.loading"
    >
      <VCard title="Uploads">
        <v-expansion-panels accordion>
          <v-expansion-panel
            v-for="(sarif, k) in state.uploads"
            :key="k"
          >
            <v-expansion-panel-title
              class="text-subtitle-1"
              v-if="sarif.results.length"
            >
              {{ sarif.sarifId }} ({{ sarif.results.length }} results)
            </v-expansion-panel-title>
            <v-expansion-panel-text v-if="sarif.results.length">
              <VSkeletonLoader
                v-if="state.loading"
                type="table"
              />
              <VTable
                v-else
                height="20rem"
                fixed-header
              >
                <thead>
                  <tr>
                    <th class="text-uppercase">
                      Rule
                    </th>
                    <th>
                      Level
                    </th>
                    <th>
                      Precision
                    </th>
                    <th>
                      Tool
                    </th>
                    <th>
                      SARIF Identifier
                    </th>
                    <th>
                      Message Text
                    </th>
                    <th>
                      Created Date
                    </th>
                  </tr>
                </thead>

                <tbody>
                  <tr
                    v-for="(result, i) in sarif.results"
                    :key="i"
                  >
                    <td>
                      {{ result.ruleId }}
                    </td>
                    <td class="text-center">
                      {{ result.level }}
                    </td>
                    <td class="text-center">
                      {{ result.precision }}
                    </td>
                    <td class="text-center">
                      {{ sarif.toolName }} {{ sarif.toolVersion }}
                    </td>
                    <td class="text-center">
                      {{ sarif.sarifId }}
                    </td>
                    <td class="text-center">
                      {{ result.messageText }}
                    </td>
                    <td class="text-center">
                      {{ new Date(sarif.createdAt).toLocaleDateString() }}
                    </td>
                  </tr>
                </tbody>
              </VTable>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </VCard>

    </VCol>

  </VRow>
</template>
