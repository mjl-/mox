package sherpats

const libTS = `export const defaultBaseURL = BASEURL

// NOTE: code below is shared between github.com/mjl-/sherpaweb and github.com/mjl-/sherpats.
// KEEP IN SYNC.

export const supportedSherpaVersion = 1

export interface Section {
	Name: string
	Docs: string
	Functions: Function[]
	Sections: Section[]
	Structs: Struct[]
	Ints: Ints[]
	Strings: Strings[]
	Version: string // only for top-level section
	SherpaVersion: number // only for top-level section
	SherpadocVersion: number // only for top-level section
}

export interface Function {
	Name: string
	Docs: string
	Params: Arg[]
	Returns: Arg[]
}

export interface Arg {
	Name: string
	Typewords: string[]
}

export interface Struct {
	Name: string
	Docs: string
	Fields: Field[]
}

export interface Field {
	Name: string
	Docs: string
	Typewords: string[]
}

export interface Ints {
	Name: string
	Docs: string
	Values: {
		Name: string
		Value: number
		Docs: string
	}[] | null
}

export interface Strings {
	Name: string
	Docs: string
	Values: {
		Name: string
		Value: string
		Docs: string
	}[] | null
}

export type NamedType = Struct | Strings | Ints
export type TypenameMap = { [k: string]: NamedType }

// verifyArg typechecks "v" against "typewords", returning a new (possibly modified) value for JSON-encoding.
// toJS indicate if the data is coming into JS. If so, timestamps are turned into JS Dates. Otherwise, JS Dates are turned into strings.
// allowUnknownKeys configures whether unknown keys in structs are allowed.
// types are the named types of the API.
export const verifyArg = (path: string, v: any, typewords: string[], toJS: boolean, allowUnknownKeys: boolean, types: TypenameMap, opts: ClientOptions): any => {
	return new verifier(types, toJS, allowUnknownKeys, opts).verify(path, v, typewords)
}

export const parse = (name: string, v: any): any => verifyArg(name, v, [name], true, false, types, defaultOptions)

class verifier {
	constructor(private types: TypenameMap, private toJS: boolean, private allowUnknownKeys: boolean, private opts: ClientOptions) {
	}

	verify(path: string, v: any, typewords: string[]): any {
		typewords = typewords.slice(0)
		const ww = typewords.shift()

		const error = (msg: string) => {
			if (path != '') {
				msg = path + ': ' + msg
			}
			throw new Error(msg)
		}

		if (typeof ww !== 'string') {
			error('bad typewords')
			return // should not be necessary, typescript doesn't see error always throws an exception?
		}
		const w: string = ww

		const ensure = (ok: boolean, expect: string): any => {
			if (!ok) {
				error('got ' + JSON.stringify(v) +  ', expected ' + expect)
			}
			return v
		}

		switch (w) {
		case 'nullable':
			if (v === null || v === undefined && this.opts.nullableOptional) {
				return v
			}
			return this.verify(path, v, typewords)
		case '[]':
			if (v === null && this.opts.slicesNullable || v === undefined && this.opts.slicesNullable && this.opts.nullableOptional) {
				return v
			}
			ensure(Array.isArray(v), "array")
			return v.map((e: any, i: number) => this.verify(path + '[' + i + ']', e, typewords))
		case '{}':
			if (v === null && this.opts.mapsNullable || v === undefined && this.opts.mapsNullable && this.opts.nullableOptional) {
				return v
			}
			ensure(v !== null || typeof v === 'object', "object")
			const r: any = {}
			for (const k in v) {
				r[k] = this.verify(path + '.' + k, v[k], typewords)
			}
			return r
		}

		ensure(typewords.length == 0, "empty typewords")
		const t = typeof v
		switch (w) {
		case 'any':
			return v
		case 'bool':
			ensure(t === 'boolean', 'bool')
			return v
		case 'int8':
		case 'uint8':
		case 'int16':
		case 'uint16':
		case 'int32':
		case 'uint32':
		case 'int64':
		case 'uint64':
			ensure(t === 'number' && Number.isInteger(v), 'integer')
			return v
		case 'float32':
		case 'float64':
			ensure(t === 'number', 'float')
			return v
		case 'int64s':
		case 'uint64s':
			ensure(t === 'number' && Number.isInteger(v) || t === 'string', 'integer fitting in float without precision loss, or string')
			return '' + v
		case 'string':
			ensure(t === 'string', 'string')
			return v
		case 'timestamp':
			if (this.toJS) {
				ensure(t === 'string', 'string, with timestamp')
				const d = new Date(v)
				if (d instanceof Date && !isNaN(d.getTime())) {
					return d
				}
				error('invalid date ' + v)
			} else {
				ensure(t === 'object' && v !== null, 'non-null object')
				ensure(v.__proto__ === Date.prototype, 'Date')
				return v.toISOString()
			}
		}

		// We're left with named types.
		const nt = this.types[w]
		if (!nt) {
			error('unknown type ' + w)
		}
		if (v === null) {
			error('bad value ' + v + ' for named type ' + w)
		}

		if (structTypes[nt.Name]) {
			const t = nt as Struct
			if (typeof v !== 'object') {
				error('bad value ' + v + ' for struct ' + w)
			}

			const r: any = {}
			for (const f of t.Fields) {
				r[f.Name] = this.verify(path + '.' + f.Name, v[f.Name], f.Typewords)
			}
			// If going to JSON also verify no unknown fields are present.
			if (!this.allowUnknownKeys) {
				const known: { [key: string]: boolean } = {}
				for (const f of t.Fields) {
					known[f.Name] = true
				}
				Object.keys(v).forEach((k) => {
					if (!known[k]) {
						error('unknown key ' + k + ' for struct ' + w)
					}
				})
			}
			return r
		} else if (stringsTypes[nt.Name]) {
			const t = nt as Strings
			if (typeof v !== 'string') {
				error('mistyped value ' + v + ' for named strings ' + t.Name)
			}
			if (!t.Values || t.Values.length === 0) {
				return v
			}
			for (const sv of t.Values) {
				if (sv.Value === v) {
					return v
				}
			}
			error('unknkown value ' + v + ' for named strings ' + t.Name)
		} else if (intsTypes[nt.Name]) {
			const t = nt as Ints
			if (typeof v !== 'number' || !Number.isInteger(v)) {
				error('mistyped value ' + v + ' for named ints ' + t.Name)
			}
			if (!t.Values || t.Values.length === 0) {
				return v
			}
			for (const sv of t.Values) {
				if (sv.Value === v) {
					return v
				}
			}
			error('unknkown value ' + v + ' for named ints ' + t.Name)
		} else {
			throw new Error('unexpected named type ' + nt)
		}
	}
}


export interface ClientOptions {
	aborter?: {abort?: () => void}
	timeoutMsec?: number
	skipParamCheck?: boolean
	skipReturnCheck?: boolean
	slicesNullable?: boolean
	mapsNullable?: boolean
	nullableOptional?: boolean
}

const _sherpaCall = async (baseURL: string, options: ClientOptions, paramTypes: string[][], returnTypes: string[][], name: string, params: any[]): Promise<any> => {
	if (!options.skipParamCheck) {
		if (params.length !== paramTypes.length) {
			return Promise.reject({ message: 'wrong number of parameters in sherpa call, saw ' + params.length + ' != expected ' + paramTypes.length })
		}
		params = params.map((v: any, index: number) => verifyArg('params[' + index + ']', v, paramTypes[index], false, false, types, options))
	}
	const simulate = async (json: string) => {
		const config = JSON.parse(json || 'null') || {}
		const waitMinMsec = config.waitMinMsec || 0
		const waitMaxMsec = config.waitMaxMsec || 0
		const wait = Math.random() * (waitMaxMsec - waitMinMsec)
		const failRate = config.failRate || 0
		return new Promise<void>((resolve, reject) => {
			if (options.aborter) {
				options.aborter.abort = () => {
					reject({ message: 'call to ' + name + ' aborted by user', code: 'sherpa:aborted' })
					reject = resolve = () => { }
				}
			}
			setTimeout(() => {
				const r = Math.random()
				if (r < failRate) {
					reject({ message: 'injected failure on ' + name, code: 'server:injected' })
				} else {
					resolve()
				}
				reject = resolve = () => { }
			}, waitMinMsec + wait)
		})
	}
	// Only simulate when there is a debug string. Otherwise it would always interfere
	// with setting options.aborter.
	let json: string = ''
	try {
		json = window.localStorage.getItem('sherpats-debug') || ''
	} catch (err) {}
	if (json) {
		await simulate(json)
	}

	// Immediately create promise, so options.aborter is changed before returning.
	const promise = new Promise((resolve, reject) => {
		let resolve1 = (v: { code: string, message: string }) => {
			resolve(v)
			resolve1 = () => { }
			reject1 = () => { }
		}
		let reject1 = (v: { code: string, message: string }) => {
			reject(v)
			resolve1 = () => { }
			reject1 = () => { }
		}

		const url = baseURL + name
		const req = new window.XMLHttpRequest()
		if (options.aborter) {
			options.aborter.abort = () => {
				req.abort()
				reject1({ code: 'sherpa:aborted', message: 'request aborted' })
			}
		}
		req.open('POST', url, true)
		if (options.timeoutMsec) {
			req.timeout = options.timeoutMsec
		}
		req.onload = () => {
			if (req.status !== 200) {
				if (req.status === 404) {
					reject1({ code: 'sherpa:badFunction', message: 'function does not exist' })
				} else {
					reject1({ code: 'sherpa:http', message: 'error calling function, HTTP status: ' + req.status })
				}
				return
			}

			let resp: any
			try {
				resp = JSON.parse(req.responseText)
			} catch (err) {
				reject1({ code: 'sherpa:badResponse', message: 'bad JSON from server' })
				return
			}
			if (resp && resp.error) {
				const err = resp.error
				reject1({ code: err.code, message: err.message })
				return
			} else if (!resp || !resp.hasOwnProperty('result')) {
				reject1({ code: 'sherpa:badResponse', message: "invalid sherpa response object, missing 'result'" })
				return
			}

			if (options.skipReturnCheck) {
				resolve1(resp.result)
				return
			}
			let result = resp.result
			try {
				if (returnTypes.length === 0) {
					if (result) {
						throw new Error('function ' + name + ' returned a value while prototype says it returns "void"')
					}
				} else if (returnTypes.length === 1) {
					result = verifyArg('result', result, returnTypes[0], true, true, types, options)
				} else {
					if (result.length != returnTypes.length) {
						throw new Error('wrong number of values returned by ' + name + ', saw ' + result.length + ' != expected ' + returnTypes.length)
					}
					result = result.map((v: any, index: number) => verifyArg('result[' + index + ']', v, returnTypes[index], true, true, types, options))
				}
			} catch (err) {
				let errmsg = 'bad types'
				if (err instanceof Error) {
					errmsg = err.message
				}
				reject1({ code: 'sherpa:badTypes', message: errmsg })
			}
			resolve1(result)
		}
		req.onerror = () => {
			reject1({ code: 'sherpa:connection', message: 'connection failed' })
		}
		req.ontimeout = () => {
			reject1({ code: 'sherpa:timeout', message: 'request timeout' })
		}
		req.setRequestHeader('Content-Type', 'application/json')
		try {
			req.send(JSON.stringify({ params: params }))
		} catch (err) {
			reject1({ code: 'sherpa:badData', message: 'cannot marshal to JSON' })
		}
	})
	return await promise
}
`
